import 'dart:convert';
import 'dart:typed_data';

import '../core/archive_exceptions.dart';
import '../core/archive_options.dart';
import '../core/archive_security.dart';
import '../util/bit_reader.dart';
import '../util/bit_writer.dart';
import '../util/byte_buffer.dart';
import '../util/checksums.dart';
import 'deflate/huffman_tree.dart';

/// Pure Dart BZip2 [Codec] supporting multi-block encoding, multi-table
/// canonical Huffman coding, multi-stream decoding, and security limits.
final class BZip2PlusCodec extends Codec<List<int>, List<int>> {
  /// Creates a [BZip2PlusCodec] with the given [options].
  const BZip2PlusCodec({this.options = const BZip2Options()});

  /// Encoding and decoding configuration.
  final BZip2Options options;

  static const int _blockMagicHi = 0x314159;
  static const int _blockMagicLo = 0x265359;
  static const int _eosMagicHi = 0x177245;
  static const int _eosMagicLo = 0x385090;
  static const int _groupSize = 50;
  static const int _maxCodeLen = 20;

  @override
  Converter<List<int>, List<int>> get encoder => _BZip2Encoder(options);

  @override
  Converter<List<int>, List<int>> get decoder => _BZip2Decoder(options);

  /// Compresses [bytes] into a standard `libbzip2`-compatible BZip2 stream.
  static Uint8List encodeBytes(
    List<int> bytes, {
    BZip2Options options = const BZip2Options(),
  }) {
    final input = asUint8List(bytes);
    final level = options.blockSize100k.clamp(1, 9);
    final maxBlockSize = level * 100000 - 19;

    final writer = MsbBitWriter(input.length ~/ 2 + 64);
    // Stream header: "BZh" + ('0' + level)
    writer
      ..writeBits(0x42, 8)
      ..writeBits(0x5a, 8)
      ..writeBits(0x68, 8)
      ..writeBits(0x30 + level, 8);

    var combinedCrc = 0;
    var pos = 0;
    final n = input.length;

    while (pos < n) {
      // Build one RLE1-encoded block while computing original block CRC.
      final blockBuf = ByteWriter(maxBlockSize < 4096 ? maxBlockSize : 4096);
      var crcState = BZip2Crc32.initialState;

      while (pos < n && blockBuf.length < maxBlockSize) {
        final b = input[pos];
        var runLen = 1;
        while (pos + runLen < n && input[pos + runLen] == b && runLen < 255) {
          runLen++;
        }
        // Check if appending this run would exceed maxBlockSize.
        final encodedRunSize = runLen >= 4 ? 5 : runLen;
        if (blockBuf.length > 0 &&
            blockBuf.length + encodedRunSize > maxBlockSize) {
          break;
        }
        for (var i = 0; i < runLen; i++) {
          crcState = BZip2Crc32.updateByte(crcState, b);
        }
        if (runLen >= 4) {
          blockBuf
            ..writeUint8(b)
            ..writeUint8(b)
            ..writeUint8(b)
            ..writeUint8(b)
            ..writeUint8(runLen - 4);
        } else {
          for (var i = 0; i < runLen; i++) {
            blockBuf.writeUint8(b);
          }
        }
        pos += runLen;
      }

      final blockCrc = BZip2Crc32.finalize(crcState);
      combinedCrc = BZip2Crc32.combine(combinedCrc, blockCrc);

      _encodeBlock(writer, blockBuf.toBytesView(), blockCrc);
    }

    // End-of-stream magic + combined CRC.
    writer
      ..writeBits(_eosMagicHi, 24)
      ..writeBits(_eosMagicLo, 24)
      ..writeBits(combinedCrc, 32);

    return writer.toBytes();
  }

  /// Decompresses a BZip2 stream (including concatenated multi-stream inputs)
  /// while enforcing [BZip2Options.securityPolicy].
  static Uint8List decodeBytes(
    List<int> bytes, {
    BZip2Options options = const BZip2Options(),
  }) {
    final input = asUint8List(bytes);
    if (input.length < 14) {
      throw const ArchiveFormatException(
        'BZip2 stream is too short (minimum 14 bytes).',
        offset: 0,
      );
    }

    final policy = options.securityPolicy;
    final maxOut = policy.effectiveSingleStreamLimit();
    final reader = MsbBitReader(input);
    final out = ByteWriter(input.length * 3);

    var streamCount = 0;
    while (reader.remainingBits >= 32) {
      final headerOffset = reader.byteOffset;
      final b0 = reader.readBits(8);
      final b1 = reader.readBits(8);
      final b2 = reader.readBits(8);
      final b3 = reader.readBits(8);

      if (b0 != 0x42 || b1 != 0x5a || b2 != 0x68 || b3 < 0x31 || b3 > 0x39) {
        if (streamCount > 0) {
          throw ArchiveFormatException(
            'Invalid trailing bytes after BZip2 stream.',
            offset: headerOffset,
          );
        }
        throw ArchiveFormatException(
          'Invalid BZip2 magic header.',
          offset: headerOffset,
        );
      }

      streamCount++;
      final blockSize100k = b3 - 0x30;
      final maxBlockBytes = blockSize100k * 100000;
      var combinedCrc = 0;

      while (true) {
        final magicOffset = reader.byteOffset;
        final magicHi = reader.readBits(24);
        final magicLo = reader.readBits(24);

        if (magicHi == _eosMagicHi && magicLo == _eosMagicLo) {
          final expectedCombined = reader.readBits(32);
          if (policy.strictChecksum && expectedCombined != combinedCrc) {
            throw ArchiveChecksumException(
              'BZip2 combined stream CRC mismatch.',
              expected: expectedCombined,
              actual: combinedCrc,
              offset: magicOffset,
            );
          }
          reader.alignToByte();
          break;
        }

        if (magicHi != _blockMagicHi || magicLo != _blockMagicLo) {
          throw ArchiveFormatException(
            'Invalid BZip2 block magic 0x${magicHi.toRadixString(16)}'
            '${magicLo.toRadixString(16).padLeft(6, '0')}.',
            offset: magicOffset,
          );
        }

        final blockCrc = _decodeBlock(
          reader: reader,
          maxBlockBytes: maxBlockBytes,
          output: out,
          policy: policy,
          maxOut: maxOut,
        );
        combinedCrc = BZip2Crc32.combine(combinedCrc, blockCrc);
      }
    }

    if (streamCount == 0) {
      throw const ArchiveFormatException('Empty or invalid BZip2 stream.');
    }

    final decoded = out.toBytes();
    policy.checkCompressionRatio(
      compressedSize: input.length,
      uncompressedSize: decoded.length,
    );
    return decoded;
  }

  // ---------------------------------------------------------------------------
  // BZip2 Block Encoder
  // ---------------------------------------------------------------------------

  static void _encodeBlock(MsbBitWriter writer, Uint8List block, int blockCrc) {
    final bwt = _forwardBwt(block);

    // Block header.
    writer
      ..writeBits(_blockMagicHi, 24)
      ..writeBits(_blockMagicLo, 24)
      ..writeBits(blockCrc, 32)
      ..writeBits(0, 1) // randomized = false
      ..writeBits(bwt.origPtr, 24);

    // Symbol presence bitmap.
    final inUse = Uint8List(256);
    for (var i = 0; i < bwt.lastCol.length; i++) {
      inUse[bwt.lastCol[i]] = 1;
    }

    final unseqToSeq = Uint8List(256);
    var nInUse = 0;
    var inUse16 = 0;
    for (var i = 0; i < 16; i++) {
      var groupUsed = false;
      for (var j = 0; j < 16; j++) {
        final sym = (i << 4) | j;
        if (inUse[sym] != 0) {
          groupUsed = true;
          unseqToSeq[sym] = nInUse++;
        }
      }
      if (groupUsed) {
        inUse16 |= 1 << (15 - i);
      }
    }

    writer.writeBits(inUse16, 16);
    for (var i = 0; i < 16; i++) {
      if ((inUse16 & (1 << (15 - i))) != 0) {
        var mask = 0;
        for (var j = 0; j < 16; j++) {
          if (inUse[(i << 4) | j] != 0) {
            mask |= 1 << (15 - j);
          }
        }
        writer.writeBits(mask, 16);
      }
    }

    final alphaSize = nInUse + 2;
    final eob = nInUse + 1;

    // Move-To-Front + RUNA/RUNB encoding.
    final mtf = Uint8List(nInUse);
    for (var i = 0; i < nInUse; i++) {
      mtf[i] = i;
    }

    final mtfSyms = <int>[];
    final mtfFreq = Int32List(alphaSize);
    var zeroRun = 0;

    void flushZeroRun() {
      while (zeroRun > 0) {
        zeroRun--;
        final sym = zeroRun & 1; // 0 = RUNA, 1 = RUNB
        mtfSyms.add(sym);
        mtfFreq[sym]++;
        zeroRun >>>= 1;
      }
    }

    for (var i = 0; i < bwt.lastCol.length; i++) {
      final seq = unseqToSeq[bwt.lastCol[i]];
      if (mtf[0] == seq) {
        zeroRun++;
      } else {
        flushZeroRun();
        var j = 1;
        var prev = mtf[0];
        mtf[0] = seq;
        while (true) {
          final curr = mtf[j];
          mtf[j] = prev;
          if (curr == seq) {
            break;
          }
          prev = curr;
          j++;
        }
        final sym = j + 1;
        mtfSyms.add(sym);
        mtfFreq[sym]++;
      }
    }
    flushZeroRun();
    mtfSyms.add(eob);
    mtfFreq[eob]++;

    final nMtf = mtfSyms.length;
    final nGroups = nMtf < 200
        ? 2
        : nMtf < 600
        ? 3
        : nMtf < 1200
        ? 4
        : nMtf < 2400
        ? 5
        : 6;
    final nSelectors = (nMtf + _groupSize - 1) ~/ _groupSize;

    // Initialize coding tables by frequency partitioning (standard libbzip2).
    final lengths = List<Uint8List>.generate(
      nGroups,
      (_) => Uint8List(alphaSize),
    );
    var remFreq = nMtf;
    var gs = 0;
    for (var t = nGroups; t >= 1; t--) {
      final target = remFreq ~/ t;
      var ge = gs - 1;
      var aFreq = 0;
      while (aFreq < target && ge < alphaSize - 1) {
        ge++;
        aFreq += mtfFreq[ge];
      }
      if (ge > gs && t != nGroups && t != 1 && ((nGroups - t) & 1) == 1) {
        aFreq -= mtfFreq[ge];
        ge--;
      }
      final tableLen = lengths[t - 1];
      for (var v = 0; v < alphaSize; v++) {
        tableLen[v] = (v >= gs && v <= ge) ? 1 : 15;
      }
      gs = ge + 1;
      remFreq -= aFreq;
    }

    // Lloyd-Max refinement iterations assigning each 50-symbol chunk to the
    // lowest-cost Huffman table.
    final selectors = Uint8List(nSelectors);
    final groupFreqs = List<Int32List>.generate(
      nGroups,
      (_) => Int32List(alphaSize),
    );
    final cost = Int32List(nGroups);

    for (var iter = 0; iter < 4; iter++) {
      for (var t = 0; t < nGroups; t++) {
        groupFreqs[t].fillRange(0, alphaSize, 0);
      }

      var selIdx = 0;
      for (var start = 0; start < nMtf; start += _groupSize) {
        final end = (start + _groupSize < nMtf) ? start + _groupSize : nMtf;
        cost.fillRange(0, nGroups, 0);
        for (var i = start; i < end; i++) {
          final sym = mtfSyms[i];
          for (var t = 0; t < nGroups; t++) {
            cost[t] += lengths[t][sym];
          }
        }
        var bestGroup = 0;
        var bestCost = cost[0];
        for (var t = 1; t < nGroups; t++) {
          if (cost[t] < bestCost) {
            bestCost = cost[t];
            bestGroup = t;
          }
        }
        selectors[selIdx++] = bestGroup;
        final freq = groupFreqs[bestGroup];
        for (var i = start; i < end; i++) {
          freq[mtfSyms[i]]++;
        }
      }

      for (var t = 0; t < nGroups; t++) {
        // Ensure every symbol in [0..alphaSize) has frequency >= 1 so every
        // BZip2 code length stays in [1..20].
        final freq = groupFreqs[t];
        for (var v = 0; v < alphaSize; v++) {
          if (freq[v] == 0) {
            freq[v] = 1;
          }
        }
        lengths[t] = DeflateHuffmanEncoder.computeLengths(freq, _maxCodeLen);
      }
    }

    // Write nGroups and nSelectors.
    writer
      ..writeBits(nGroups, 3)
      ..writeBits(nSelectors, 15);

    // Write MTF-encoded selectors in unary.
    final selPos = Uint8List(nGroups);
    for (var i = 0; i < nGroups; i++) {
      selPos[i] = i;
    }
    for (var i = 0; i < nSelectors; i++) {
      final target = selectors[i];
      var j = 0;
      while (selPos[j] != target) {
        j++;
      }
      for (var k = j; k > 0; k--) {
        selPos[k] = selPos[k - 1];
      }
      selPos[0] = target;
      for (var k = 0; k < j; k++) {
        writer.writeBits(1, 1);
      }
      writer.writeBits(0, 1);
    }

    // Write delta-encoded Huffman code lengths for each table.
    final codes = List<Int32List>.generate(
      nGroups,
      (_) => Int32List(alphaSize),
    );
    for (var t = 0; t < nGroups; t++) {
      final len = lengths[t];
      var curr = len[0];
      writer.writeBits(curr, 5);
      for (var v = 0; v < alphaSize; v++) {
        final desired = len[v];
        while (curr < desired) {
          writer.writeBits(2, 2); // binary 10 => +1
          curr++;
        }
        while (curr > desired) {
          writer.writeBits(3, 2); // binary 11 => -1
          curr--;
        }
        writer.writeBits(0, 1);
      }
      _assignCanonicalMsbCodes(len, codes[t]);
    }

    // Write all MTF symbols in 50-symbol chunks.
    var selIdx = 0;
    for (var start = 0; start < nMtf; start += _groupSize) {
      final end = (start + _groupSize < nMtf) ? start + _groupSize : nMtf;
      final group = selectors[selIdx++];
      final groupCodes = codes[group];
      final groupLens = lengths[group];
      for (var i = start; i < end; i++) {
        final sym = mtfSyms[i];
        writer.writeBits(groupCodes[sym], groupLens[sym]);
      }
    }
  }

  static void _assignCanonicalMsbCodes(Uint8List lengths, Int32List codes) {
    var minLen = _maxCodeLen;
    var maxLen = 0;
    for (final len in lengths) {
      if (len < minLen) {
        minLen = len;
      }
      if (len > maxLen) {
        maxLen = len;
      }
    }
    var code = 0;
    for (var bitLen = minLen; bitLen <= maxLen; bitLen++) {
      for (var sym = 0; sym < lengths.length; sym++) {
        if (lengths[sym] == bitLen) {
          codes[sym] = code++;
        }
      }
      code <<= 1;
    }
  }

  /// O(n log n) cyclic Burrows-Wheeler Transform using prefix-doubling radix
  /// sort (worst-case guaranteed without quadratic blowup).
  static ({Uint8List lastCol, int origPtr}) _forwardBwt(Uint8List data) {
    final n = data.length;
    if (n <= 1) {
      return (lastCol: Uint8List.fromList(data), origPtr: 0);
    }

    final sa = Int32List(n);
    final tmpSa = Int32List(n);
    var rank = Int32List(n);
    var nextRank = Int32List(n);
    final bucketSize = n > 256 ? n : 256;
    final count = Int32List(bucketSize);

    // Initial counting sort by single byte.
    for (var i = 0; i < n; i++) {
      count[data[i]]++;
    }
    for (var i = 1; i < 256; i++) {
      count[i] += count[i - 1];
    }
    for (var i = n - 1; i >= 0; i--) {
      sa[--count[data[i]]] = i;
    }

    rank[sa[0]] = 0;
    var classes = 1;
    for (var i = 1; i < n; i++) {
      if (data[sa[i]] != data[sa[i - 1]]) {
        classes++;
      }
      rank[sa[i]] = classes - 1;
    }

    for (var step = 1; step < n && classes < n; step <<= 1) {
      for (var i = 0; i < n; i++) {
        var p = sa[i] - step;
        if (p < 0) {
          p += n;
        }
        tmpSa[i] = p;
      }

      count.fillRange(0, classes, 0);
      for (var i = 0; i < n; i++) {
        count[rank[tmpSa[i]]]++;
      }
      for (var i = 1; i < classes; i++) {
        count[i] += count[i - 1];
      }
      for (var i = n - 1; i >= 0; i--) {
        final idx = tmpSa[i];
        sa[--count[rank[idx]]] = idx;
      }

      nextRank[sa[0]] = 0;
      classes = 1;
      for (var i = 1; i < n; i++) {
        final cur = sa[i];
        final prev = sa[i - 1];
        var cur2 = cur + step;
        if (cur2 >= n) {
          cur2 -= n;
        }
        var prev2 = prev + step;
        if (prev2 >= n) {
          prev2 -= n;
        }
        if (rank[cur] != rank[prev] || rank[cur2] != rank[prev2]) {
          classes++;
        }
        nextRank[cur] = classes - 1;
      }

      final swap = rank;
      rank = nextRank;
      nextRank = swap;
    }

    final lastCol = Uint8List(n);
    var origPtr = 0;
    for (var i = 0; i < n; i++) {
      final pos = sa[i];
      if (pos == 0) {
        origPtr = i;
        lastCol[i] = data[n - 1];
      } else {
        lastCol[i] = data[pos - 1];
      }
    }

    return (lastCol: lastCol, origPtr: origPtr);
  }

  // ---------------------------------------------------------------------------
  // BZip2 Block Decoder
  // ---------------------------------------------------------------------------

  static int _decodeBlock({
    required MsbBitReader reader,
    required int maxBlockBytes,
    required ByteWriter output,
    required ArchiveSecurityPolicy policy,
    required int? maxOut,
  }) {
    final expectedBlockCrc = reader.readBits(32);
    final randomized = reader.readBit() == 1;
    final origPtr = reader.readBits(24);

    // Read symbol presence bitmap.
    final inUse16 = reader.readBits(16);
    final seqToUnseq = Uint8List(256);
    var nInUse = 0;
    for (var i = 0; i < 16; i++) {
      if ((inUse16 & (1 << (15 - i))) != 0) {
        final mask = reader.readBits(16);
        for (var j = 0; j < 16; j++) {
          if ((mask & (1 << (15 - j))) != 0) {
            seqToUnseq[nInUse++] = (i << 4) | j;
          }
        }
      }
    }

    if (nInUse == 0) {
      throw ArchiveFormatException(
        'BZip2 block defines zero symbols in use.',
        offset: reader.byteOffset,
      );
    }

    final alphaSize = nInUse + 2;
    final eob = nInUse + 1;

    final nGroups = reader.readBits(3);
    if (nGroups < 2 || nGroups > 6) {
      throw ArchiveFormatException(
        'Invalid BZip2 Huffman group count: $nGroups.',
        offset: reader.byteOffset,
      );
    }

    final nSelectors = reader.readBits(15);
    if (nSelectors < 1) {
      throw ArchiveFormatException(
        'Invalid BZip2 selector count: $nSelectors.',
        offset: reader.byteOffset,
      );
    }

    // Decode MTF-encoded selectors.
    final selectorMtf = Uint8List(nGroups);
    for (var i = 0; i < nGroups; i++) {
      selectorMtf[i] = i;
    }
    final selectors = Uint8List(nSelectors);
    for (var i = 0; i < nSelectors; i++) {
      var j = 0;
      while (reader.readBit() == 1) {
        j++;
        if (j >= nGroups) {
          throw ArchiveFormatException(
            'BZip2 selector MTF index out of range.',
            offset: reader.byteOffset,
          );
        }
      }
      final v = selectorMtf[j];
      for (var k = j; k > 0; k--) {
        selectorMtf[k] = selectorMtf[k - 1];
      }
      selectorMtf[0] = v;
      selectors[i] = v;
    }

    // Decode canonical Huffman trees for each group.
    final tables = List<_BZip2HuffmanTable>.generate(nGroups, (_) {
      final lengths = Uint8List(alphaSize);
      var curr = reader.readBits(5);
      for (var sym = 0; sym < alphaSize; sym++) {
        while (reader.readBit() == 1) {
          curr += reader.readBit() == 0 ? 1 : -1;
          if (curr < 1 || curr > _maxCodeLen) {
            throw ArchiveFormatException(
              'BZip2 Huffman code length out of range ($curr).',
              offset: reader.byteOffset,
            );
          }
        }
        lengths[sym] = curr;
      }
      return _BZip2HuffmanTable.fromLengths(lengths);
    });

    // Decode MTF + RUNA/RUNB symbols into BWT last-column buffer.
    final mtf = Uint8List(nInUse);
    for (var i = 0; i < nInUse; i++) {
      mtf[i] = i;
    }
    final bwtBuf = ByteWriter(maxBlockBytes < 4096 ? maxBlockBytes : 4096);

    var groupIdx = 0;
    var groupPos = 0;
    var currentTable = tables[selectors[0]];

    int nextSym() {
      if (groupPos == 0) {
        if (groupIdx >= nSelectors) {
          throw ArchiveFormatException(
            'BZip2 selector table exhausted before end of block.',
            offset: reader.byteOffset,
          );
        }
        currentTable = tables[selectors[groupIdx++]];
        groupPos = _groupSize;
      }
      groupPos--;
      return currentTable.decode(reader);
    }

    var sym = nextSym();
    while (sym != eob) {
      if (sym == 0 || sym == 1) {
        var run = 0;
        var power = 1;
        while (sym == 0 || sym == 1) {
          run += (sym == 0 ? 1 : 2) * power;
          power <<= 1;
          if (bwtBuf.length + run > maxBlockBytes) {
            throw ArchiveFormatException(
              'BZip2 RLE run exceeds declared block size ($maxBlockBytes).',
              offset: reader.byteOffset,
            );
          }
          sym = nextSym();
        }
        final ch = seqToUnseq[mtf[0]];
        for (var i = 0; i < run; i++) {
          bwtBuf.writeUint8(ch);
        }
      } else {
        final idx = sym - 1;
        if (idx >= nInUse) {
          throw ArchiveFormatException(
            'Invalid BZip2 MTF symbol $sym.',
            offset: reader.byteOffset,
          );
        }
        final seq = mtf[idx];
        for (var k = idx; k > 0; k--) {
          mtf[k] = mtf[k - 1];
        }
        mtf[0] = seq;
        if (bwtBuf.length >= maxBlockBytes) {
          throw ArchiveFormatException(
            'BZip2 block exceeds declared block size ($maxBlockBytes).',
            offset: reader.byteOffset,
          );
        }
        bwtBuf.writeUint8(seqToUnseq[seq]);
        sym = nextSym();
      }
    }

    final bwt = bwtBuf.toBytesView();
    final n = bwt.length;
    if (n == 0 || origPtr >= n) {
      throw ArchiveFormatException(
        'Invalid BZip2 BWT origin pointer ($origPtr for block length $n).',
        offset: reader.byteOffset,
      );
    }

    // Inverse BWT via LF-mapping.
    final cftab = Int32List(257);
    for (var i = 0; i < n; i++) {
      cftab[bwt[i] + 1]++;
    }
    for (var i = 1; i <= 256; i++) {
      cftab[i] += cftab[i - 1];
    }

    final tt = Int32List(n);
    for (var i = 0; i < n; i++) {
      tt[cftab[bwt[i]]++] = i;
    }

    // Walk inverse BWT + optional legacy derandomization + inverse RLE1.
    var tPos = tt[origPtr];
    var crcState = BZip2Crc32.initialState;
    var prevByte = -1;
    var runCount = 0;
    var rNToGo = 0;
    var rTPos = 0;

    void emitByte(int byte) {
      if (maxOut != null && output.length + 1 > maxOut) {
        throw ArchiveSecurityException(
          'BZip2 decompressed output exceeds policy limit ($maxOut bytes).',
          violation: ArchiveSecurityViolation.entrySizeLimitExceeded,
        );
      }
      output.writeUint8(byte);
      crcState = BZip2Crc32.updateByte(crcState, byte);
    }

    for (var i = 0; i < n; i++) {
      var ch = bwt[tPos];
      tPos = tt[tPos];

      if (randomized) {
        if (rNToGo == 0) {
          rNToGo = _bzip2RNums[rTPos];
          rTPos = (rTPos + 1) & 511;
        }
        rNToGo--;
        if (rNToGo == 1) {
          ch ^= 1;
        }
      }

      if (runCount == 4) {
        // `ch` is the repeat count (0..255) for `prevByte`.
        for (var r = 0; r < ch; r++) {
          emitByte(prevByte);
        }
        prevByte = -1;
        runCount = 0;
      } else {
        emitByte(ch);
        if (ch == prevByte) {
          runCount++;
        } else {
          prevByte = ch;
          runCount = 1;
        }
      }
    }

    final actualBlockCrc = BZip2Crc32.finalize(crcState);
    if (policy.strictChecksum && actualBlockCrc != expectedBlockCrc) {
      throw ArchiveChecksumException(
        'BZip2 block CRC-32 mismatch.',
        expected: expectedBlockCrc,
        actual: actualBlockCrc,
      );
    }
    return actualBlockCrc;
  }

  /// Standard libbzip2 512-entry randomization table (for legacy v0.9 files).
  static const List<int> _bzip2RNums = <int>[
    619,
    720,
    127,
    481,
    931,
    816,
    813,
    233,
    566,
    247,
    985,
    724,
    205,
    454,
    863,
    491,
    741,
    242,
    949,
    214,
    733,
    859,
    335,
    708,
    621,
    574,
    73,
    654,
    730,
    472,
    419,
    436,
    278,
    496,
    867,
    210,
    399,
    680,
    480,
    51,
    878,
    465,
    811,
    169,
    869,
    675,
    611,
    697,
    867,
    561,
    862,
    687,
    507,
    283,
    482,
    129,
    807,
    591,
    733,
    623,
    150,
    238,
    59,
    379,
    684,
    877,
    625,
    169,
    643,
    105,
    170,
    607,
    520,
    932,
    727,
    476,
    693,
    425,
    174,
    647,
    73,
    122,
    335,
    530,
    442,
    853,
    695,
    249,
    445,
    515,
    909,
    545,
    703,
    919,
    874,
    474,
    882,
    500,
    594,
    612,
    641,
    801,
    220,
    162,
    819,
    984,
    589,
    513,
    495,
    799,
    161,
    604,
    958,
    533,
    221,
    400,
    386,
    867,
    600,
    782,
    382,
    596,
    414,
    171,
    516,
    375,
    682,
    485,
    911,
    276,
    98,
    553,
    163,
    354,
    666,
    933,
    424,
    341,
    533,
    870,
    227,
    730,
    475,
    186,
    263,
    647,
    537,
    686,
    600,
    224,
    469,
    68,
    770,
    919,
    190,
    373,
    294,
    822,
    808,
    206,
    184,
    943,
    795,
    384,
    383,
    461,
    404,
    758,
    839,
    887,
    715,
    67,
    618,
    276,
    204,
    918,
    873,
    777,
    604,
    560,
    951,
    160,
    578,
    722,
    79,
    804,
    96,
    409,
    713,
    940,
    652,
    934,
    970,
    447,
    318,
    353,
    859,
    672,
    112,
    785,
    645,
    863,
    803,
    350,
    139,
    93,
    354,
    99,
    820,
    908,
    609,
    772,
    154,
    274,
    580,
    184,
    79,
    626,
    630,
    742,
    653,
    282,
    762,
    623,
    680,
    81,
    927,
    626,
    789,
    125,
    411,
    521,
    938,
    300,
    821,
    78,
    343,
    175,
    128,
    250,
    170,
    774,
    972,
    275,
    999,
    639,
    495,
    78,
    352,
    126,
    857,
    956,
    358,
    619,
    580,
    124,
    737,
    594,
    701,
    612,
    669,
    112,
    134,
    694,
    363,
    992,
    809,
    743,
    168,
    974,
    944,
    375,
    748,
    52,
    600,
    747,
    642,
    182,
    862,
    81,
    344,
    805,
    988,
    739,
    511,
    655,
    814,
    334,
    249,
    515,
    897,
    955,
    664,
    981,
    649,
    113,
    974,
    459,
    893,
    228,
    433,
    837,
    553,
    268,
    926,
    240,
    102,
    654,
    459,
    51,
    686,
    754,
    806,
    760,
    493,
    403,
    415,
    394,
    687,
    700,
    946,
    670,
    656,
    610,
    738,
    392,
    760,
    799,
    887,
    653,
    978,
    321,
    576,
    617,
    626,
    502,
    894,
    679,
    243,
    440,
    680,
    879,
    194,
    572,
    640,
    724,
    926,
    56,
    204,
    700,
    707,
    151,
    457,
    449,
    797,
    195,
    791,
    558,
    945,
    679,
    297,
    59,
    87,
    824,
    713,
    663,
    412,
    693,
    342,
    606,
    134,
    108,
    571,
    364,
    631,
    212,
    174,
    643,
    304,
    329,
    343,
    97,
    430,
    751,
    497,
    314,
    983,
    374,
    822,
    928,
    140,
    206,
    73,
    263,
    980,
    736,
    876,
    478,
    430,
    305,
    170,
    514,
    364,
    692,
    829,
    82,
    855,
    953,
    676,
    246,
    369,
    970,
    294,
    750,
    807,
    827,
    150,
    790,
    288,
    923,
    804,
    378,
    215,
    828,
    592,
    281,
    565,
    555,
    710,
    82,
    896,
    831,
    547,
    261,
    524,
    462,
    293,
    465,
    502,
    56,
    661,
    821,
    976,
    991,
    658,
    869,
    905,
    758,
    745,
    193,
    768,
    550,
    608,
    933,
    378,
    286,
    215,
    979,
    792,
    961,
    61,
    688,
    793,
    644,
    986,
    403,
    106,
    366,
    905,
    644,
    372,
    567,
    466,
    434,
    645,
    210,
    389,
    550,
    919,
    135,
    780,
    773,
    635,
    389,
    707,
    100,
    626,
    958,
    165,
    504,
    920,
    176,
    193,
    713,
    857,
    265,
    203,
    50,
    668,
    108,
    645,
    990,
    626,
    197,
    510,
    357,
    358,
    850,
    858,
    364,
    936,
    638,
  ];
}

final class _BZip2HuffmanTable {
  _BZip2HuffmanTable({
    required this.minLen,
    required this.maxLen,
    required this.limit,
    required this.base,
    required this.perm,
  });

  factory _BZip2HuffmanTable.fromLengths(Uint8List lengths) {
    final alphaSize = lengths.length;
    var minLen = 20;
    var maxLen = 0;
    for (final len in lengths) {
      if (len < minLen) {
        minLen = len;
      }
      if (len > maxLen) {
        maxLen = len;
      }
    }

    final perm = Uint16List(alphaSize);
    var pp = 0;
    for (var i = minLen; i <= maxLen; i++) {
      for (var sym = 0; sym < alphaSize; sym++) {
        if (lengths[sym] == i) {
          perm[pp++] = sym;
        }
      }
    }

    final base = Int32List(23);
    final limit = Int32List(23);
    for (var sym = 0; sym < alphaSize; sym++) {
      base[lengths[sym] + 1]++;
    }
    for (var i = 1; i < 23; i++) {
      base[i] += base[i - 1];
    }

    var vec = 0;
    for (var i = minLen; i <= maxLen; i++) {
      vec += base[i + 1] - base[i];
      limit[i] = vec - 1;
      vec <<= 1;
    }
    for (var i = minLen + 1; i <= maxLen; i++) {
      base[i] = ((limit[i - 1] + 1) << 1) - base[i];
    }

    return _BZip2HuffmanTable(
      minLen: minLen,
      maxLen: maxLen,
      limit: limit,
      base: base,
      perm: perm,
    );
  }

  final int minLen;
  final int maxLen;
  final Int32List limit;
  final Int32List base;
  final Uint16List perm;

  @pragma('vm:prefer-inline')
  int decode(MsbBitReader reader) {
    var zn = minLen;
    var zvec = reader.readBits(zn);
    while (zvec > limit[zn]) {
      zn++;
      if (zn > maxLen) {
        throw ArchiveFormatException(
          'Invalid BZip2 Huffman code.',
          offset: reader.byteOffset,
        );
      }
      zvec = (zvec << 1) | reader.readBit();
    }
    final idx = zvec - base[zn];
    if (idx < 0 || idx >= perm.length) {
      throw ArchiveFormatException(
        'BZip2 Huffman symbol index out of bounds.',
        offset: reader.byteOffset,
      );
    }
    return perm[idx];
  }
}

final class _BZip2Encoder extends Converter<List<int>, List<int>> {
  const _BZip2Encoder(this.options);

  final BZip2Options options;

  @override
  Uint8List convert(List<int> input) =>
      BZip2PlusCodec.encodeBytes(input, options: options);

  @override
  Sink<List<int>> startChunkedConversion(Sink<List<int>> sink) =>
      _BZip2BufferedSink(sink, convert);
}

final class _BZip2Decoder extends Converter<List<int>, List<int>> {
  const _BZip2Decoder(this.options);

  final BZip2Options options;

  @override
  Uint8List convert(List<int> input) =>
      BZip2PlusCodec.decodeBytes(input, options: options);

  @override
  Sink<List<int>> startChunkedConversion(Sink<List<int>> sink) =>
      _BZip2BufferedSink(sink, convert);
}

final class _BZip2BufferedSink implements Sink<List<int>> {
  _BZip2BufferedSink(this._outSink, this._transform);

  final Sink<List<int>> _outSink;
  final Uint8List Function(List<int>) _transform;
  final ByteWriter _buffer = ByteWriter();

  @override
  void add(List<int> data) => _buffer.writeBytes(data);

  @override
  void close() {
    _outSink.add(_transform(_buffer.toBytesView()));
    _outSink.close();
  }
}

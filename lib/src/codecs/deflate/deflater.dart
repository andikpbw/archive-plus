import 'dart:typed_data';

import '../../util/bit_writer.dart';
import 'deflate_tables.dart';
import 'huffman_tree.dart';

/// Pure Dart RFC 1951 raw DEFLATE compressor supporting compression levels
/// `0` (stored) through `9` (best), with automatic optimal block selection
/// among Stored, Fixed Huffman, and Dynamic Huffman blocks.
final class DeflateDeflater {
  DeflateDeflater._();

  static const int _windowSize = 32768;
  static const int _windowMask = _windowSize - 1;
  static const int _hashBits = 15;
  static const int _hashSize = 1 << _hashBits;
  static const int _hashMask = _hashSize - 1;
  static const int _minMatch = 3;
  static const int _maxMatch = 258;
  static const int _maxBlockSymbols = 32768;

  /// Compresses [input] using raw RFC 1951 DEFLATE at [level] (`0`..`9`).
  static Uint8List deflate(Uint8List input, {int level = 6}) {
    final clampedLevel = level.clamp(0, 9);
    if (clampedLevel == 0 || input.isEmpty) {
      return _encodeStoredAll(input);
    }

    final maxChain = switch (clampedLevel) {
      1 => 4,
      2 => 8,
      3 => 16,
      4 => 32,
      5 => 64,
      6 => 128,
      7 => 256,
      8 => 512,
      _ => 1024,
    };
    final niceLength = switch (clampedLevel) {
      1 => 8,
      2 => 16,
      3 => 32,
      4 => 48,
      5 => 96,
      6 => 128,
      7 => 192,
      _ => 258,
    };
    final useLazy = clampedLevel >= 4;

    final writer = LsbBitWriter(input.length ~/ 2 + 64);
    final head = Int32List(_hashSize)..fillRange(0, _hashSize, -1);
    final prev = Int32List(_windowSize)..fillRange(0, _windowSize, -1);

    // Token buffer for the current block:
    // litLenVal[i] < 256 => literal byte;
    // litLenVal[i] >= 256 => match length = litLenVal[i] - 256 + 3 (3..258),
    //                        distVal[i] = match distance (1..32768).
    final tokenVal = Uint16List(_maxBlockSymbols);
    final tokenDist = Uint16List(_maxBlockSymbols);
    final litLenFreq = Int32List(286);
    final distFreq = Int32List(30);
    var tokenCount = 0;
    var blockStart = 0;

    int hash3(int pos) {
      return ((input[pos] << 10) ^ (input[pos + 1] << 5) ^ input[pos + 2]) &
          _hashMask;
    }

    void insertHash(int pos) {
      if (pos + 2 >= input.length) {
        return;
      }
      final h = hash3(pos);
      prev[pos & _windowMask] = head[h];
      head[h] = pos;
    }

    ({int length, int distance}) findBestMatch(int pos, int prevBestLen) {
      if (pos + _minMatch > input.length) {
        return (length: 0, distance: 0);
      }
      final h = hash3(pos);
      var candidate = head[h];
      var bestLen = prevBestLen;
      var bestDist = 0;
      var steps = maxChain;
      final minPos = pos - _windowSize;
      final maxLen = (input.length - pos) < _maxMatch
          ? (input.length - pos)
          : _maxMatch;
      if (bestLen >= maxLen) {
        return (length: 0, distance: 0);
      }

      while (candidate >= 0 && candidate > minPos && steps-- > 0) {
        if (input[candidate + bestLen] == input[pos + bestLen] &&
            input[candidate] == input[pos] &&
            input[candidate + 1] == input[pos + 1] &&
            input[candidate + 2] == input[pos + 2]) {
          var len = 3;
          while (len < maxLen && input[candidate + len] == input[pos + len]) {
            len++;
          }
          if (len > bestLen) {
            bestLen = len;
            bestDist = pos - candidate;
            if (bestLen >= niceLength || bestLen == maxLen) {
              break;
            }
          }
        }
        final next = prev[candidate & _windowMask];
        if (next >= candidate) {
          break;
        }
        candidate = next;
      }
      return (length: bestLen, distance: bestDist);
    }

    void flushBlock(int blockEnd, bool isFinal) {
      litLenFreq[256] = 1; // End-of-block symbol.
      _writeBestBlock(
        writer: writer,
        input: input,
        blockStart: blockStart,
        blockEnd: blockEnd,
        tokenVal: tokenVal,
        tokenDist: tokenDist,
        tokenCount: tokenCount,
        litLenFreq: litLenFreq,
        distFreq: distFreq,
        isFinal: isFinal,
      );
      tokenCount = 0;
      litLenFreq.fillRange(0, 286, 0);
      distFreq.fillRange(0, 30, 0);
      blockStart = blockEnd;
    }

    var pos = 0;
    final n = input.length;

    while (pos < n) {
      final match = findBestMatch(pos, _minMatch - 1);
      insertHash(pos);

      final chosenLen = match.length;
      var chosenDist = match.distance;

      // Lazy matching: check if pos + 1 yields a strictly better match.
      if (useLazy &&
          chosenDist > 0 &&
          chosenLen < niceLength &&
          pos + 1 + _minMatch <= n) {
        final nextMatch = findBestMatch(pos + 1, chosenLen);
        if (nextMatch.distance > 0 && nextMatch.length > chosenLen) {
          // Emit current byte as literal and let next iteration take the better match.
          chosenDist = 0;
        }
      }

      if (chosenDist > 0) {
        final lenCodeIdx = DeflateTables.lengthToCodeIndex[chosenLen];
        final distCode = DeflateTables.distanceToCode(chosenDist);
        tokenVal[tokenCount] = 256 + (chosenLen - _minMatch);
        tokenDist[tokenCount] = chosenDist;
        tokenCount++;
        litLenFreq[257 + lenCodeIdx]++;
        distFreq[distCode]++;

        // Insert hashes for skipped positions inside the match.
        final skipEnd = pos + chosenLen;
        for (var p = pos + 1; p < skipEnd; p++) {
          insertHash(p);
        }
        pos = skipEnd;
      } else {
        final literal = input[pos];
        tokenVal[tokenCount] = literal;
        tokenDist[tokenCount] = 0;
        tokenCount++;
        litLenFreq[literal]++;
        pos++;
      }

      if (tokenCount >= _maxBlockSymbols || pos - blockStart >= 65535) {
        flushBlock(pos, pos >= n);
      }
    }

    if (tokenCount > 0 || blockStart == 0) {
      flushBlock(n, true);
    }

    return writer.toBytes();
  }

  static Uint8List _encodeStoredAll(Uint8List input) {
    final writer = LsbBitWriter(input.length + 16);
    if (input.isEmpty) {
      writer.writeBits(1, 1); // BFINAL = 1
      writer.writeBits(0, 2); // BTYPE = 0 (stored)
      writer.writeAlignedUint16LE(0);
      writer.writeAlignedUint16LE(0xffff);
      return writer.toBytes();
    }
    var offset = 0;
    while (offset < input.length) {
      final chunkLen = (input.length - offset) > 65535
          ? 65535
          : (input.length - offset);
      final isFinal = offset + chunkLen >= input.length;
      writer.writeBits(isFinal ? 1 : 0, 1);
      writer.writeBits(0, 2);
      writer.writeAlignedUint16LE(chunkLen);
      writer.writeAlignedUint16LE(chunkLen ^ 0xffff);
      writer.writeAlignedBytes(input, offset, offset + chunkLen);
      offset += chunkLen;
    }
    return writer.toBytes();
  }

  static void _writeBestBlock({
    required LsbBitWriter writer,
    required Uint8List input,
    required int blockStart,
    required int blockEnd,
    required Uint16List tokenVal,
    required Uint16List tokenDist,
    required int tokenCount,
    required Int32List litLenFreq,
    required Int32List distFreq,
    required bool isFinal,
  }) {
    final rawLen = blockEnd - blockStart;

    // 1. Compute stored block cost (worst-case +7 alignment bits + 3 header + 32 len/nlen).
    final storedBits = rawLen <= 65535 ? (3 + 7 + 32 + rawLen * 8) : 0x7fffffff;

    // 2. Compute fixed Huffman block cost.
    final fixedBits =
        3 +
        _computeHuffmanDataBits(
          litLenFreq,
          distFreq,
          DeflateTables.fixedLitLenLengths,
          DeflateTables.fixedDistLengths,
        );

    // 3. Build dynamic Huffman trees and compute total header + data cost.
    final dynLitLenLengths = DeflateHuffmanEncoder.computeLengths(
      litLenFreq,
      15,
    );
    var dynDistLengths = DeflateHuffmanEncoder.computeLengths(distFreq, 15);
    var hasAnyDist = false;
    for (final len in dynDistLengths) {
      if (len > 0) {
        hasAnyDist = true;
        break;
      }
    }
    if (!hasAnyDist) {
      // RFC 1951 requires HDIST >= 1; emit a single zero-length entry.
      dynDistLengths = Uint8List(1);
    }

    var hlit = 286;
    while (hlit > 257 && dynLitLenLengths[hlit - 1] == 0) {
      hlit--;
    }
    var hdist = dynDistLengths.length;
    while (hdist > 1 && dynDistLengths[hdist - 1] == 0) {
      hdist--;
    }

    final combinedLengths = Uint8List(hlit + hdist);
    combinedLengths.setRange(0, hlit, dynLitLenLengths);
    combinedLengths.setRange(hlit, hlit + hdist, dynDistLengths);

    final rleEncoded = _rleEncodeCodeLengths(combinedLengths);
    final clFreq = Int32List(19);
    var activeClSymbols = 0;
    for (var i = 0; i < rleEncoded.symbols.length; i++) {
      final sym = rleEncoded.symbols[i];
      if (clFreq[sym] == 0) {
        activeClSymbols++;
      }
      clFreq[sym]++;
    }

    // Ensure code-length Huffman tree is complete (at least 2 active symbols)
    // for strict compatibility with zlib's inftrees.c validator.
    late final Uint8List clLengths;
    late final DeflateHuffmanEncoder clEncoder;
    var hclen = 4;
    var dynBits = 0x7fffffff;

    if (activeClSymbols >= 2) {
      clLengths = DeflateHuffmanEncoder.computeLengths(clFreq, 7);
      clEncoder = DeflateHuffmanEncoder.fromLengths(clLengths);

      hclen = 19;
      while (hclen > 4 &&
          clLengths[DeflateTables.codeLengthOrder[hclen - 1]] == 0) {
        hclen--;
      }

      var dynHeaderBits = 3 + 5 + 5 + 4 + (hclen * 3);
      for (var i = 0; i < rleEncoded.symbols.length; i++) {
        final sym = rleEncoded.symbols[i];
        dynHeaderBits += clLengths[sym];
        if (sym == 16) {
          dynHeaderBits += 2;
        } else if (sym == 17) {
          dynHeaderBits += 3;
        } else if (sym == 18) {
          dynHeaderBits += 7;
        }
      }
      dynBits =
          dynHeaderBits +
          _computeHuffmanDataBits(
            litLenFreq,
            distFreq,
            dynLitLenLengths,
            dynDistLengths,
          );
    }

    // Pick the smallest encoding.
    if (storedBits <= fixedBits && storedBits <= dynBits) {
      writer.writeBits(isFinal ? 1 : 0, 1);
      writer.writeBits(0, 2);
      writer.writeAlignedUint16LE(rawLen);
      writer.writeAlignedUint16LE(rawLen ^ 0xffff);
      writer.writeAlignedBytes(input, blockStart, blockEnd);
      return;
    }

    if (fixedBits <= dynBits) {
      writer.writeBits(isFinal ? 1 : 0, 1);
      writer.writeBits(1, 2);
      _writeTokens(
        writer: writer,
        tokenVal: tokenVal,
        tokenDist: tokenDist,
        tokenCount: tokenCount,
        litLenEnc: DeflateHuffmanEncoder.fixedLitLen,
        distEnc: DeflateHuffmanEncoder.fixedDist,
      );
      return;
    }

    // Dynamic Huffman block.
    writer.writeBits(isFinal ? 1 : 0, 1);
    writer.writeBits(2, 2);
    writer.writeBits(hlit - 257, 5);
    writer.writeBits(hdist - 1, 5);
    writer.writeBits(hclen - 4, 4);

    for (var i = 0; i < hclen; i++) {
      writer.writeBits(clLengths[DeflateTables.codeLengthOrder[i]], 3);
    }

    for (var i = 0; i < rleEncoded.symbols.length; i++) {
      final sym = rleEncoded.symbols[i];
      writer.writeBits(clEncoder.codes[sym], clEncoder.lengths[sym]);
      if (sym == 16) {
        writer.writeBits(rleEncoded.extras[i], 2);
      } else if (sym == 17) {
        writer.writeBits(rleEncoded.extras[i], 3);
      } else if (sym == 18) {
        writer.writeBits(rleEncoded.extras[i], 7);
      }
    }

    final dynLitLenEnc = DeflateHuffmanEncoder.fromLengths(dynLitLenLengths);
    final dynDistEnc = DeflateHuffmanEncoder.fromLengths(dynDistLengths);
    _writeTokens(
      writer: writer,
      tokenVal: tokenVal,
      tokenDist: tokenDist,
      tokenCount: tokenCount,
      litLenEnc: dynLitLenEnc,
      distEnc: dynDistEnc,
    );
  }

  static int _computeHuffmanDataBits(
    Int32List litLenFreq,
    Int32List distFreq,
    Uint8List litLenLengths,
    Uint8List distLengths,
  ) {
    var bits = 0;
    for (var sym = 0; sym <= 256; sym++) {
      final freq = litLenFreq[sym];
      if (freq > 0) {
        bits += freq * litLenLengths[sym];
      }
    }
    for (var i = 0; i < 29; i++) {
      final freq = litLenFreq[257 + i];
      if (freq > 0) {
        bits +=
            freq * (litLenLengths[257 + i] + DeflateTables.lengthExtraBits[i]);
      }
    }
    for (var i = 0; i < distFreq.length && i < distLengths.length; i++) {
      final freq = distFreq[i];
      if (freq > 0) {
        bits += freq * (distLengths[i] + DeflateTables.distExtraBits[i]);
      }
    }
    return bits;
  }

  static void _writeTokens({
    required LsbBitWriter writer,
    required Uint16List tokenVal,
    required Uint16List tokenDist,
    required int tokenCount,
    required DeflateHuffmanEncoder litLenEnc,
    required DeflateHuffmanEncoder distEnc,
  }) {
    for (var i = 0; i < tokenCount; i++) {
      final val = tokenVal[i];
      if (val < 256) {
        writer.writeBits(litLenEnc.codes[val], litLenEnc.lengths[val]);
      } else {
        final matchLen = val - 256 + _minMatch;
        final lenIdx = DeflateTables.lengthToCodeIndex[matchLen];
        final lenSym = 257 + lenIdx;
        writer.writeBits(litLenEnc.codes[lenSym], litLenEnc.lengths[lenSym]);
        final lenExtra = DeflateTables.lengthExtraBits[lenIdx];
        if (lenExtra > 0) {
          writer.writeBits(
            matchLen - DeflateTables.lengthBase[lenIdx],
            lenExtra,
          );
        }

        final dist = tokenDist[i];
        final distCode = DeflateTables.distanceToCode(dist);
        writer.writeBits(distEnc.codes[distCode], distEnc.lengths[distCode]);
        final distExtra = DeflateTables.distExtraBits[distCode];
        if (distExtra > 0) {
          writer.writeBits(dist - DeflateTables.distBase[distCode], distExtra);
        }
      }
    }
    // End-of-block symbol 256.
    writer.writeBits(litLenEnc.codes[256], litLenEnc.lengths[256]);
  }

  static ({List<int> symbols, List<int> extras}) _rleEncodeCodeLengths(
    Uint8List lengths,
  ) {
    final symbols = <int>[];
    final extras = <int>[];
    var i = 0;
    final n = lengths.length;

    while (i < n) {
      final value = lengths[i];
      var run = 1;
      while (i + run < n && lengths[i + run] == value) {
        run++;
      }

      if (value == 0) {
        var remaining = run;
        while (remaining >= 11) {
          final chunk = remaining > 138 ? 138 : remaining;
          symbols.add(18);
          extras.add(chunk - 11);
          remaining -= chunk;
        }
        if (remaining >= 3) {
          symbols.add(17);
          extras.add(remaining - 3);
          remaining = 0;
        }
        while (remaining > 0) {
          symbols.add(0);
          extras.add(0);
          remaining--;
        }
      } else {
        symbols.add(value);
        extras.add(0);
        var remaining = run - 1;
        while (remaining >= 3) {
          final chunk = remaining > 6 ? 6 : remaining;
          symbols.add(16);
          extras.add(chunk - 3);
          remaining -= chunk;
        }
        while (remaining > 0) {
          symbols.add(value);
          extras.add(0);
          remaining--;
        }
      }
      i += run;
    }

    return (symbols: symbols, extras: extras);
  }
}

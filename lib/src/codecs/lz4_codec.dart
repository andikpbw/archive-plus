import 'dart:convert';
import 'dart:typed_data';

import '../core/archive_exceptions.dart';
import '../core/archive_options.dart';
import '../util/byte_buffer.dart';
import '../util/checksums.dart';

/// Pure Dart LZ4 Frame Format (v1.6) [Codec] offering ultra-fast compression
/// and decompression with XXH32 integrity verification.
final class Lz4PlusCodec extends Codec<List<int>, List<int>> {
  /// Creates an [Lz4PlusCodec] with the given [options].
  const Lz4PlusCodec({this.options = const Lz4Options()});

  /// Encoding and decoding configuration.
  final Lz4Options options;

  static const int _frameMagic = 0x184d2204;
  static const int _skippableMagicMin = 0x184d2a50;
  static const int _skippableMagicMax = 0x184d2a5f;

  static const int _hashLog = 14;
  static const int _hashSize = 1 << _hashLog;
  static const int _minMatch = 4;
  static const int _mfLimit = 12;
  static const int _lastLiterals = 5;

  @override
  Converter<List<int>, List<int>> get encoder => _Lz4Encoder(options);

  @override
  Converter<List<int>, List<int>> get decoder => _Lz4Decoder(options);

  /// Compresses [bytes] into an official LZ4 Frame Format byte stream.
  static Uint8List encodeBytes(
    List<int> bytes, {
    Lz4Options options = const Lz4Options(),
  }) {
    final input = asUint8List(bytes);
    final out = ByteWriter(input.length + 32);

    // 4-byte frame magic (little-endian).
    out.writeUint32LE(_frameMagic);

    // Frame descriptor (FLG + BD + optional 8-byte content size).
    var flg = 0x40; // Version = 01 (bits 7..6)
    flg |= 0x20; // Block Independence = 1
    if (options.blockChecksum) {
      flg |= 0x10;
    }
    if (options.includeContentSize) {
      flg |= 0x08;
    }
    if (options.contentChecksum) {
      flg |= 0x04;
    }

    final bd = (options.blockSize.id & 0x07) << 4;

    final descWriter = ByteWriter(12)
      ..writeUint8(flg)
      ..writeUint8(bd);
    if (options.includeContentSize) {
      descWriter.writeUint64LE(input.length);
    }
    final descBytes = descWriter.toBytesView();
    final headerChecksum = (Xxh32.compute(descBytes) >>> 8) & 0xff;

    out
      ..writeBytes(descBytes)
      ..writeUint8(headerChecksum);

    // Encode independent data blocks.
    final maxBlockSize = options.blockSize.maxBytes;
    var offset = 0;
    while (offset < input.length) {
      final chunkEnd = (offset + maxBlockSize < input.length)
          ? offset + maxBlockSize
          : input.length;
      final chunk = Uint8List.sublistView(input, offset, chunkEnd);
      final compressed = _compressBlock(chunk);

      if (compressed.length < chunk.length) {
        out
          ..writeUint32LE(compressed.length)
          ..writeBytes(compressed);
        if (options.blockChecksum) {
          out.writeUint32LE(Xxh32.compute(compressed));
        }
      } else {
        // Store block uncompressed (MSB bit 31 = 1).
        out
          ..writeUint32LE(chunk.length | 0x80000000)
          ..writeBytes(chunk);
        if (options.blockChecksum) {
          out.writeUint32LE(Xxh32.compute(chunk));
        }
      }
      offset = chunkEnd;
    }

    // EndMark (0x00000000).
    out.writeUint32LE(0);

    // Optional content checksum.
    if (options.contentChecksum) {
      out.writeUint32LE(Xxh32.compute(input));
    }

    return out.toBytes();
  }

  /// Decompresses an LZ4 Frame Format stream (supporting multiple concatenated
  /// frames and skippable frames) while enforcing [Lz4Options.securityPolicy].
  static Uint8List decodeBytes(
    List<int> bytes, {
    Lz4Options options = const Lz4Options(),
  }) {
    final input = asUint8List(bytes);
    if (input.length < 7) {
      throw const ArchiveFormatException(
        'LZ4 frame is too short (minimum 7 bytes).',
        offset: 0,
      );
    }

    final policy = options.securityPolicy;
    final maxOut = policy.effectiveSingleStreamLimit();
    final reader = ByteReader(input);
    final combined = ByteWriter(input.length * 2);
    var frameCount = 0;

    while (!reader.isEof) {
      final magicOffset = reader.offset;
      final magic = reader.readUint32LE();

      // Handle skippable frames (0x184D2A50..0x184D2A5F).
      if (magic >= _skippableMagicMin && magic <= _skippableMagicMax) {
        final skipLen = reader.readUint32LE();
        reader.skip(skipLen);
        continue;
      }

      if (magic != _frameMagic) {
        throw ArchiveFormatException(
          'Invalid LZ4 frame magic: 0x${magic.toRadixString(16)}.',
          offset: magicOffset,
        );
      }

      frameCount++;
      final descStart = reader.offset;
      final flg = reader.readUint8();
      final bd = reader.readUint8();

      final version = (flg >>> 6) & 0x03;
      if (version != 1) {
        throw ArchiveFormatException(
          'Unsupported LZ4 frame version $version (expected 1).',
          offset: descStart,
        );
      }
      if ((flg & 0x02) != 0) {
        throw ArchiveFormatException(
          'Reserved LZ4 FLG bit 1 is set.',
          offset: descStart,
        );
      }

      final blockIndependence = (flg & 0x20) != 0;
      final hasBlockChecksum = (flg & 0x10) != 0;
      final hasContentSize = (flg & 0x08) != 0;
      final hasContentChecksum = (flg & 0x04) != 0;
      final hasDictId = (flg & 0x01) != 0;

      final blockMaxId = (bd >>> 4) & 0x07;
      final blockMaxSpec = Lz4BlockSize.fromId(blockMaxId);
      if (blockMaxSpec == null || (bd & 0x8f) != 0) {
        throw ArchiveFormatException(
          'Invalid LZ4 block descriptor byte: 0x${bd.toRadixString(16)}.',
          offset: descStart + 1,
        );
      }

      int? expectedContentSize;
      if (hasContentSize) {
        expectedContentSize = reader.readUint64LE();
        if (maxOut != null && combined.length + expectedContentSize > maxOut) {
          throw ArchiveSecurityException(
            'LZ4 declared content size ($expectedContentSize bytes) exceeds '
            'policy limit ($maxOut bytes).',
            violation: ArchiveSecurityViolation.entrySizeLimitExceeded,
            offset: descStart + 2,
          );
        }
      }
      if (hasDictId) {
        reader.skip(4);
      }

      final descEnd = reader.offset;
      final expectedHc = reader.readUint8();
      if (policy.strictChecksum) {
        final actualHc =
            (Xxh32.compute(input, start: descStart, end: descEnd) >>> 8) & 0xff;
        if (actualHc != expectedHc) {
          throw ArchiveChecksumException(
            'LZ4 frame header checksum mismatch.',
            expected: expectedHc,
            actual: actualHc,
            offset: descEnd,
          );
        }
      }

      final frameOut = ByteWriter(expectedContentSize ?? input.length * 2);

      // Decode blocks until EndMark (0).
      while (true) {
        final blockSizeRaw = reader.readUint32LE();
        if (blockSizeRaw == 0) {
          break;
        }
        final isUncompressed = (blockSizeRaw & 0x80000000) != 0;
        final blockBytesLen = blockSizeRaw & 0x7fffffff;
        final blockData = reader.readBytesView(blockBytesLen);

        if (hasBlockChecksum) {
          final expectedBlockCrc = reader.readUint32LE();
          if (policy.strictChecksum) {
            final actualBlockCrc = Xxh32.compute(blockData);
            if (actualBlockCrc != expectedBlockCrc) {
              throw ArchiveChecksumException(
                'LZ4 block XXH32 checksum mismatch.',
                expected: expectedBlockCrc,
                actual: actualBlockCrc,
                offset: reader.offset - 4,
              );
            }
          }
        }

        if (isUncompressed) {
          if (maxOut != null &&
              combined.length + frameOut.length + blockData.length > maxOut) {
            throw ArchiveSecurityException(
              'LZ4 output exceeds policy limit ($maxOut bytes).',
              violation: ArchiveSecurityViolation.entrySizeLimitExceeded,
            );
          }
          frameOut.writeBytes(blockData);
        } else {
          final remainingLimit = maxOut == null
              ? null
              : maxOut - combined.length - frameOut.length;
          final history = blockIndependence ? null : frameOut.toBytesView();
          final decodedBlock = _decompressBlock(
            blockData,
            maxBlockOutput: blockMaxSpec.maxBytes,
            maxTotalRemaining: remainingLimit,
            history: history,
          );
          frameOut.writeBytes(decodedBlock);
        }
      }

      final frameBytes = frameOut.toBytesView();

      if (hasContentSize && frameBytes.length != expectedContentSize) {
        throw ArchiveFormatException(
          'LZ4 decoded frame length (${frameBytes.length}) does not match '
          'header content size ($expectedContentSize).',
          offset: reader.offset,
        );
      }

      if (hasContentChecksum) {
        final expectedContentCrc = reader.readUint32LE();
        if (policy.strictChecksum) {
          final actualContentCrc = Xxh32.compute(frameBytes);
          if (actualContentCrc != expectedContentCrc) {
            throw ArchiveChecksumException(
              'LZ4 content XXH32 checksum mismatch.',
              expected: expectedContentCrc,
              actual: actualContentCrc,
              offset: reader.offset - 4,
            );
          }
        }
      }

      combined.writeBytes(frameBytes);
    }

    if (frameCount == 0) {
      throw const ArchiveFormatException('No valid LZ4 data frame found.');
    }

    final result = combined.toBytes();
    policy.checkCompressionRatio(
      compressedSize: input.length,
      uncompressedSize: result.length,
    );
    return result;
  }

  // ---------------------------------------------------------------------------
  // Raw LZ4 Block Compression & Decompression
  // ---------------------------------------------------------------------------

  static int _hash4(Uint8List data, int pos) {
    final seq =
        (data[pos] |
            (data[pos + 1] << 8) |
            (data[pos + 2] << 16) |
            (data[pos + 3] << 24)) &
        0xffffffff;
    return imul32(seq, 2654435761) >>> (32 - _hashLog);
  }

  static Uint8List _compressBlock(Uint8List src) {
    final n = src.length;
    if (n < _mfLimit + 1) {
      // Emit purely literal block.
      final out = ByteWriter(n + 8);
      _writeLiteralsOnly(out, src, 0, n);
      return out.toBytes();
    }

    final out = ByteWriter(n + 16);
    final hashTable = Int32List(_hashSize)..fillRange(0, _hashSize, -1);
    final matchLimit = n - _lastLiterals;
    final mfLimit = n - _mfLimit;

    var anchor = 0;
    var ip = 0;
    hashTable[_hash4(src, 0)] = 0;
    ip = 1;

    while (ip <= mfLimit) {
      var step = 1;
      var searchMatchNb = 64;
      var ref = -1;

      while (true) {
        final h = _hash4(src, ip);
        ref = hashTable[h];
        hashTable[h] = ip;

        if (ref >= 0 &&
            (ip - ref) <= 65535 &&
            src[ref] == src[ip] &&
            src[ref + 1] == src[ip + 1] &&
            src[ref + 2] == src[ip + 2] &&
            src[ref + 3] == src[ip + 3]) {
          break;
        }

        ip += step;
        if (ip > mfLimit) {
          _writeLiteralsOnly(out, src, anchor, n - anchor);
          return out.toBytes();
        }
        step = searchMatchNb++ >>> 6;
      }

      // Extend match backwards into pending literals when possible.
      while (ip > anchor && ref > 0 && src[ip - 1] == src[ref - 1]) {
        ip--;
        ref--;
      }

      final literalLen = ip - anchor;
      final offset = ip - ref;

      // Measure forward match length (already matched 4 bytes).
      var matchLen = _minMatch;
      while (ip + matchLen < matchLimit &&
          src[ref + matchLen] == src[ip + matchLen]) {
        matchLen++;
      }

      final mlCode = matchLen - _minMatch;
      final tokenLit = literalLen >= 15 ? 15 : literalLen;
      final tokenMatch = mlCode >= 15 ? 15 : mlCode;
      out.writeUint8((tokenLit << 4) | tokenMatch);

      if (literalLen >= 15) {
        var rem = literalLen - 15;
        while (rem >= 255) {
          out.writeUint8(255);
          rem -= 255;
        }
        out.writeUint8(rem);
      }

      out
        ..writeBytes(src, anchor, anchor + literalLen)
        ..writeUint16LE(offset);

      if (mlCode >= 15) {
        var rem = mlCode - 15;
        while (rem >= 255) {
          out.writeUint8(255);
          rem -= 255;
        }
        out.writeUint8(rem);
      }

      ip += matchLen;
      anchor = ip;
      if (ip > mfLimit) {
        break;
      }
      hashTable[_hash4(src, ip - 2)] = ip - 2;
    }

    _writeLiteralsOnly(out, src, anchor, n - anchor);
    return out.toBytes();
  }

  static void _writeLiteralsOnly(
    ByteWriter out,
    Uint8List src,
    int start,
    int literalLen,
  ) {
    if (literalLen <= 0) {
      return;
    }
    final tokenLit = literalLen >= 15 ? 15 : literalLen;
    out.writeUint8(tokenLit << 4);
    if (literalLen >= 15) {
      var rem = literalLen - 15;
      while (rem >= 255) {
        out.writeUint8(255);
        rem -= 255;
      }
      out.writeUint8(rem);
    }
    out.writeBytes(src, start, start + literalLen);
  }

  static Uint8List _decompressBlock(
    Uint8List src, {
    required int maxBlockOutput,
    required int? maxTotalRemaining,
    Uint8List? history,
  }) {
    final limit =
        (maxTotalRemaining != null && maxTotalRemaining < maxBlockOutput)
        ? maxTotalRemaining
        : maxBlockOutput;

    var out = Uint8List(src.length * 2 < 256 ? 256 : src.length * 2);
    var outLen = 0;

    void ensureOut(int additional) {
      final needed = outLen + additional;
      if (needed > limit) {
        throw ArchiveSecurityException(
          'LZ4 block output ($needed bytes) exceeds allowed limit ($limit bytes).',
          violation: ArchiveSecurityViolation.entrySizeLimitExceeded,
        );
      }
      if (needed <= out.length) {
        return;
      }
      var cap = out.length * 2;
      while (cap < needed) {
        cap *= 2;
      }
      if (cap > limit) {
        cap = limit;
      }
      final next = Uint8List(cap);
      next.setRange(0, outLen, out);
      out = next;
    }

    var ip = 0;
    final srcEnd = src.length;
    final histLen = history?.length ?? 0;

    while (ip < srcEnd) {
      final token = src[ip++];
      var literalLen = token >>> 4;
      if (literalLen == 15) {
        int extra;
        do {
          if (ip >= srcEnd) {
            throw const ArchiveFormatException(
              'Truncated LZ4 literal length extension.',
            );
          }
          extra = src[ip++];
          literalLen += extra;
        } while (extra == 255);
      }

      if (ip + literalLen > srcEnd) {
        throw const ArchiveFormatException(
          'Truncated LZ4 literal payload in block.',
        );
      }
      ensureOut(literalLen);
      out.setRange(outLen, outLen + literalLen, src, ip);
      outLen += literalLen;
      ip += literalLen;

      if (ip >= srcEnd) {
        break; // Last sequence ends after literals.
      }

      if (ip + 2 > srcEnd) {
        throw const ArchiveFormatException('Truncated LZ4 match offset.');
      }
      final offset = src[ip] | (src[ip + 1] << 8);
      ip += 2;
      if (offset == 0) {
        throw const ArchiveFormatException('Invalid LZ4 match offset 0.');
      }

      var matchLen = (token & 0x0f) + _minMatch;
      if ((token & 0x0f) == 15) {
        int extra;
        do {
          if (ip >= srcEnd) {
            throw const ArchiveFormatException(
              'Truncated LZ4 match length extension.',
            );
          }
          extra = src[ip++];
          matchLen += extra;
        } while (extra == 255);
      }

      if (offset > outLen + histLen) {
        throw ArchiveFormatException(
          'LZ4 match offset ($offset) exceeds decoded history '
          '(${outLen + histLen}).',
        );
      }

      ensureOut(matchLen);
      if (offset <= outLen) {
        var srcPos = outLen - offset;
        if (offset >= matchLen) {
          out.setRange(outLen, outLen + matchLen, out, srcPos);
          outLen += matchLen;
        } else if (offset == 1) {
          final fill = out[srcPos];
          out.fillRange(outLen, outLen + matchLen, fill);
          outLen += matchLen;
        } else {
          for (var i = 0; i < matchLen; i++) {
            out[outLen++] = out[srcPos++];
          }
        }
      } else {
        // Dependent block referencing prior frame history.
        final histStart = histLen - (offset - outLen);
        var remaining = matchLen;
        var hPos = histStart;
        while (remaining > 0 && hPos < histLen) {
          out[outLen++] = history![hPos++];
          remaining--;
        }
        var curPos = 0;
        while (remaining > 0) {
          out[outLen++] = out[curPos++];
          remaining--;
        }
      }
    }

    final result = Uint8List(outLen);
    result.setRange(0, outLen, out);
    return result;
  }
}

final class _Lz4Encoder extends Converter<List<int>, List<int>> {
  const _Lz4Encoder(this.options);

  final Lz4Options options;

  @override
  Uint8List convert(List<int> input) =>
      Lz4PlusCodec.encodeBytes(input, options: options);

  @override
  Sink<List<int>> startChunkedConversion(Sink<List<int>> sink) =>
      _Lz4BufferedSink(sink, convert);
}

final class _Lz4Decoder extends Converter<List<int>, List<int>> {
  const _Lz4Decoder(this.options);

  final Lz4Options options;

  @override
  Uint8List convert(List<int> input) =>
      Lz4PlusCodec.decodeBytes(input, options: options);

  @override
  Sink<List<int>> startChunkedConversion(Sink<List<int>> sink) =>
      _Lz4BufferedSink(sink, convert);
}

final class _Lz4BufferedSink implements Sink<List<int>> {
  _Lz4BufferedSink(this._outSink, this._transform);

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

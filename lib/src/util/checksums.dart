import 'dart:typed_data';

import 'byte_buffer.dart';

/// Standard IEEE 802.3 CRC-32 checksum calculator (used by ZIP and GZIP).
final class Crc32 {
  Crc32._();

  static final Uint32List _table = _buildTable();

  static Uint32List _buildTable() {
    final table = Uint32List(256);
    for (var i = 0; i < 256; i++) {
      var c = i;
      for (var j = 0; j < 8; j++) {
        c = (c & 1) != 0 ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[i] = c & 0xffffffff;
    }
    return table;
  }

  /// Computes the CRC-32 checksum of [bytes] (or slice `[start, end)`).
  static int compute(List<int> bytes, [int start = 0, int? end]) {
    return update(0, bytes, start, end);
  }

  /// Updates an existing [crc] with additional [bytes].
  static int update(int crc, List<int> bytes, [int start = 0, int? end]) {
    final table = _table;
    final actualEnd = end ?? bytes.length;
    var c = (crc ^ 0xffffffff) & 0xffffffff;
    for (var i = start; i < actualEnd; i++) {
      c = table[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) & 0xffffffff;
  }

  /// Creates an incremental [Crc32Sink] for streaming updates.
  static Crc32Sink sink() => Crc32Sink();
}

/// Incremental streaming CRC-32 accumulator.
final class Crc32Sink {
  /// Creates a new [Crc32Sink] initialized to `0`.
  Crc32Sink();

  int _crc = 0;

  /// Current CRC-32 digest value.
  int get value => _crc;

  /// Feeds [bytes] into the running CRC-32 calculation.
  void add(List<int> bytes, [int start = 0, int? end]) {
    _crc = Crc32.update(_crc, bytes, start, end);
  }

  /// Resets the accumulator back to its initial state.
  void reset() {
    _crc = 0;
  }
}

/// RFC 1950 Adler-32 checksum calculator (used by ZLIB).
final class Adler32 {
  Adler32._();

  static const int _base = 65521;
  static const int _nmax = 5552;

  /// Computes the Adler-32 checksum of [bytes] (or slice `[start, end)`).
  static int compute(List<int> bytes, [int start = 0, int? end]) {
    return update(1, bytes, start, end);
  }

  /// Updates an existing [adler] checksum with additional [bytes].
  static int update(int adler, List<int> bytes, [int start = 0, int? end]) {
    var s1 = adler & 0xffff;
    var s2 = (adler >>> 16) & 0xffff;
    var i = start;
    final actualEnd = end ?? bytes.length;

    while (i < actualEnd) {
      final chunkEnd = (i + _nmax < actualEnd) ? i + _nmax : actualEnd;
      while (i < chunkEnd) {
        s1 += bytes[i++] & 0xff;
        s2 += s1;
      }
      s1 %= _base;
      s2 %= _base;
    }
    return ((s2 << 16) | s1) & 0xffffffff;
  }

  /// Creates an incremental [Adler32Sink] for streaming updates.
  static Adler32Sink sink() => Adler32Sink();
}

/// Incremental streaming Adler-32 accumulator.
final class Adler32Sink {
  /// Creates a new [Adler32Sink] initialized to `1`.
  Adler32Sink();

  int _adler = 1;

  /// Current Adler-32 digest value.
  int get value => _adler;

  /// Feeds [bytes] into the running Adler-32 calculation.
  void add(List<int> bytes, [int start = 0, int? end]) {
    _adler = Adler32.update(_adler, bytes, start, end);
  }

  /// Resets the accumulator back to `1`.
  void reset() {
    _adler = 1;
  }
}

/// BZip2 big-endian (MSB-first) CRC-32 calculator.
final class BZip2Crc32 {
  BZip2Crc32._();

  static final Uint32List _table = _buildTable();

  static Uint32List _buildTable() {
    final table = Uint32List(256);
    for (var i = 0; i < 256; i++) {
      var c = (i << 24) & 0xffffffff;
      for (var j = 0; j < 8; j++) {
        c = (c & 0x80000000) != 0
            ? (((c << 1) ^ 0x04c11db7) & 0xffffffff)
            : ((c << 1) & 0xffffffff);
      }
      table[i] = c;
    }
    return table;
  }

  /// Initial raw CRC state (`0xffffffff`).
  static const int initialState = 0xffffffff;

  /// Updates raw BZip2 CRC [state] with a single [byte].
  @pragma('vm:prefer-inline')
  static int updateByte(int state, int byte) {
    return (((state << 8) & 0xffffffff) ^
            _table[((state >>> 24) ^ byte) & 0xff]) &
        0xffffffff;
  }

  /// Finalizes raw BZip2 CRC [state] by inverting all bits.
  @pragma('vm:prefer-inline')
  static int finalize(int state) => (state ^ 0xffffffff) & 0xffffffff;

  /// Computes the BZip2 CRC-32 of [bytes].
  static int compute(List<int> bytes, [int start = 0, int? end]) {
    var state = initialState;
    final actualEnd = end ?? bytes.length;
    for (var i = start; i < actualEnd; i++) {
      state = updateByte(state, bytes[i]);
    }
    return finalize(state);
  }

  /// Combines a block's [blockCrc] into the running [combinedCrc].
  @pragma('vm:prefer-inline')
  static int combine(int combinedCrc, int blockCrc) {
    return (rotl32(combinedCrc, 1) ^ (blockCrc & 0xffffffff)) & 0xffffffff;
  }
}

/// Official 32-bit xxHash (XXH32) checksum calculator (used by LZ4 Frame).
///
/// Uses Web/JS-safe 32-bit arithmetic ([imul32], [rotl32]) so hashes are
/// bit-identical across Dart VM, JavaScript, and WebAssembly.
final class Xxh32 {
  Xxh32._();

  static const int _prime1 = 0x9e3779b1;
  static const int _prime2 = 0x85ebca77;
  static const int _prime3 = 0xc2b2ae3d;
  static const int _prime4 = 0x27d4eb2f;
  static const int _prime5 = 0x165667b1;

  static int _readU32LE(List<int> data, int pos) {
    return ((data[pos] & 0xff) |
            ((data[pos + 1] & 0xff) << 8) |
            ((data[pos + 2] & 0xff) << 16) |
            ((data[pos + 3] & 0xff) << 24)) &
        0xffffffff;
  }

  /// Computes the XXH32 digest of [bytes] (or slice `[start, end)`) with
  /// optional [seed] (defaults to `0`).
  static int compute(List<int> bytes, {int start = 0, int? end, int seed = 0}) {
    final actualEnd = end ?? bytes.length;
    final len = actualEnd - start;
    var p = start;
    int h32;

    if (len >= 16) {
      var v1 = (seed + _prime1 + _prime2) & 0xffffffff;
      var v2 = (seed + _prime2) & 0xffffffff;
      var v3 = seed & 0xffffffff;
      var v4 = (seed - _prime1) & 0xffffffff;
      final limit = actualEnd - 16;

      while (p <= limit) {
        v1 = imul32(
          rotl32((v1 + imul32(_readU32LE(bytes, p), _prime2)) & 0xffffffff, 13),
          _prime1,
        );
        p += 4;
        v2 = imul32(
          rotl32((v2 + imul32(_readU32LE(bytes, p), _prime2)) & 0xffffffff, 13),
          _prime1,
        );
        p += 4;
        v3 = imul32(
          rotl32((v3 + imul32(_readU32LE(bytes, p), _prime2)) & 0xffffffff, 13),
          _prime1,
        );
        p += 4;
        v4 = imul32(
          rotl32((v4 + imul32(_readU32LE(bytes, p), _prime2)) & 0xffffffff, 13),
          _prime1,
        );
        p += 4;
      }

      h32 =
          (rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)) &
          0xffffffff;
    } else {
      h32 = (seed + _prime5) & 0xffffffff;
    }

    h32 = (h32 + len) & 0xffffffff;

    while (p + 4 <= actualEnd) {
      h32 = (h32 + imul32(_readU32LE(bytes, p), _prime3)) & 0xffffffff;
      h32 = imul32(rotl32(h32, 17), _prime4);
      p += 4;
    }

    while (p < actualEnd) {
      h32 = (h32 + imul32(bytes[p] & 0xff, _prime5)) & 0xffffffff;
      h32 = imul32(rotl32(h32, 11), _prime1);
      p++;
    }

    h32 ^= h32 >>> 15;
    h32 = imul32(h32, _prime2);
    h32 ^= h32 >>> 13;
    h32 = imul32(h32, _prime3);
    h32 ^= h32 >>> 16;

    return h32 & 0xffffffff;
  }
}

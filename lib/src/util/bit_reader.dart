import 'dart:typed_data';

import '../core/archive_exceptions.dart';

/// Least-significant-bit-first bit reader (used by RFC 1951 DEFLATE).
final class LsbBitReader {
  /// Creates an [LsbBitReader] over `bytes` starting at [offset] up to [end].
  LsbBitReader(this._bytes, {int offset = 0, int? end})
    : _bytePos = offset,
      _end = end ?? _bytes.length;

  final Uint8List _bytes;
  int _bytePos;
  final int _end;
  int _bitBuf = 0;
  int _bitCount = 0;

  /// Current effective byte offset (counting unconsumed whole bytes in the
  /// bit buffer).
  int get byteOffset => _bytePos - (_bitCount >> 3);

  /// Remaining whole bytes available when aligned.
  int get remainingBytes => (_end - _bytePos) + (_bitCount >> 3);

  /// Ensures at least [count] bits are buffered (up to 24 bits), returning
  /// `true` if available or `false` on EOF.
  @pragma('vm:prefer-inline')
  bool ensureBits(int count) {
    while (_bitCount < count && _bytePos < _end) {
      _bitBuf |= _bytes[_bytePos++] << _bitCount;
      _bitCount += 8;
    }
    return _bitCount >= count;
  }

  /// Peeks up to 24 bits without consuming them.
  ///
  /// Missing trailing bits past EOF are zero-padded for table lookup, and
  /// callers verify actual bit availability before dropping.
  @pragma('vm:prefer-inline')
  int peekBits(int count) {
    while (_bitCount < count && _bytePos < _end) {
      _bitBuf |= _bytes[_bytePos++] << _bitCount;
      _bitCount += 8;
    }
    return _bitBuf & ((1 << count) - 1);
  }

  /// Consumes [count] previously peeked bits.
  @pragma('vm:prefer-inline')
  void dropBits(int count) {
    if (count > _bitCount) {
      throw ArchiveFormatException(
        'Unexpected end of bit stream.',
        offset: _bytePos,
      );
    }
    _bitBuf >>>= count;
    _bitCount -= count;
  }

  /// Reads [count] bits (0..24) in LSB-first order.
  @pragma('vm:prefer-inline')
  int readBits(int count) {
    if (count == 0) {
      return 0;
    }
    if (!ensureBits(count)) {
      throw ArchiveFormatException(
        'Unexpected end of bit stream while reading $count bits.',
        offset: _bytePos,
      );
    }
    final value = _bitBuf & ((1 << count) - 1);
    _bitBuf >>>= count;
    _bitCount -= count;
    return value;
  }

  /// Discards 0..7 bits to align on the next byte boundary.
  void alignToByte() {
    final skip = _bitCount & 7;
    if (skip > 0) {
      _bitBuf >>>= skip;
      _bitCount -= skip;
    }
  }

  /// Reads an aligned unsigned 16-bit little-endian integer.
  int readAlignedUint16LE() {
    alignToByte();
    final lo = readBits(8);
    final hi = readBits(8);
    return lo | (hi << 8);
  }

  /// Reads [count] byte-aligned bytes into [target] starting at [targetOffset].
  void readAlignedBytes(Uint8List target, int targetOffset, int count) {
    alignToByte();
    var written = 0;
    while (written < count && _bitCount >= 8) {
      target[targetOffset + written] = _bitBuf & 0xff;
      _bitBuf >>>= 8;
      _bitCount -= 8;
      written++;
    }
    final rem = count - written;
    if (rem > 0) {
      if (_bytePos + rem > _end) {
        throw ArchiveFormatException(
          'Unexpected end of stream reading stored block ($rem bytes needed).',
          offset: _bytePos,
        );
      }
      target.setRange(
        targetOffset + written,
        targetOffset + count,
        _bytes,
        _bytePos,
      );
      _bytePos += rem;
    }
  }
}

/// Most-significant-bit-first bit reader (used by BZip2).
final class MsbBitReader {
  /// Creates an [MsbBitReader] over `bytes` starting at [offset] up to [end].
  MsbBitReader(this._bytes, {int offset = 0, int? end})
    : _bytePos = offset,
      _end = end ?? _bytes.length;

  final Uint8List _bytes;
  int _bytePos;
  final int _end;
  int _bitBuf = 0;
  int _bitCount = 0;

  /// Current byte offset.
  int get byteOffset => _bytePos - (_bitCount >> 3);

  /// Whether all bytes and buffered bits have been consumed.
  bool get isEof => _bytePos >= _end && _bitCount == 0;

  /// Number of remaining unread bits.
  int get remainingBits => (_end - _bytePos) * 8 + _bitCount;

  /// Reads a single bit (0 or 1).
  @pragma('vm:prefer-inline')
  int readBit() {
    if (_bitCount == 0) {
      if (_bytePos >= _end) {
        throw ArchiveFormatException(
          'Unexpected end of MSB bit stream.',
          offset: _bytePos,
        );
      }
      _bitBuf = _bytes[_bytePos++];
      _bitCount = 8;
    }
    _bitCount--;
    return (_bitBuf >>> _bitCount) & 1;
  }

  /// Reads [count] bits (0..32) in MSB-first order.
  int readBits(int count) {
    if (count == 0) {
      return 0;
    }
    if (count <= 24) {
      while (_bitCount < count) {
        if (_bytePos >= _end) {
          throw ArchiveFormatException(
            'Unexpected end of MSB bit stream while reading $count bits.',
            offset: _bytePos,
          );
        }
        _bitBuf = ((_bitBuf << 8) | _bytes[_bytePos++]) & 0xffffffff;
        _bitCount += 8;
      }
      _bitCount -= count;
      return (_bitBuf >>> _bitCount) & ((1 << count) - 1);
    }
    // Split > 24-bit reads to stay safely inside 32-bit operations on Web/JS.
    final hiCount = count - 16;
    final hi = readBits(hiCount);
    final lo = readBits(16);
    return ((hi << 16) | lo) & 0xffffffff;
  }

  /// Aligns to the next byte boundary by discarding trailing padding bits.
  void alignToByte() {
    final discard = _bitCount & 7;
    if (discard > 0) {
      _bitCount -= discard;
    }
  }
}

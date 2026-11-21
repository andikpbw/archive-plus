import 'dart:typed_data';

import 'byte_buffer.dart';

/// Least-significant-bit-first bit writer (used by RFC 1951 DEFLATE).
final class LsbBitWriter {
  /// Creates an [LsbBitWriter] with the given [initialCapacity].
  LsbBitWriter([int initialCapacity = 256])
    : _writer = ByteWriter(initialCapacity);

  final ByteWriter _writer;
  int _bitBuf = 0;
  int _bitCount = 0;

  /// Writes [count] bits (0..24) from [value] in LSB-first order.
  @pragma('vm:prefer-inline')
  void writeBits(int value, int count) {
    if (count == 0) {
      return;
    }
    _bitBuf |= (value & ((1 << count) - 1)) << _bitCount;
    _bitCount += count;
    while (_bitCount >= 8) {
      _writer.writeUint8(_bitBuf & 0xff);
      _bitBuf >>>= 8;
      _bitCount -= 8;
    }
  }

  /// Pads the current byte with zero bits if not already byte-aligned.
  void alignToByte() {
    if (_bitCount > 0) {
      _writer.writeUint8(_bitBuf & 0xff);
      _bitBuf = 0;
      _bitCount = 0;
    }
  }

  /// Writes an aligned 16-bit little-endian unsigned integer.
  void writeAlignedUint16LE(int value) {
    alignToByte();
    _writer.writeUint16LE(value);
  }

  /// Writes byte-aligned raw bytes.
  void writeAlignedBytes(List<int> bytes, [int start = 0, int? end]) {
    alignToByte();
    _writer.writeBytes(bytes, start, end);
  }

  /// Flushes any remaining bits and returns the encoded [Uint8List].
  Uint8List toBytes() {
    alignToByte();
    return _writer.toBytes();
  }
}

/// Most-significant-bit-first bit writer (used by BZip2).
final class MsbBitWriter {
  /// Creates an [MsbBitWriter] with the given [initialCapacity].
  MsbBitWriter([int initialCapacity = 256])
    : _writer = ByteWriter(initialCapacity);

  final ByteWriter _writer;
  int _bitBuf = 0;
  int _bitCount = 0;

  /// Writes [count] bits (0..32) from [value] in MSB-first order.
  void writeBits(int value, int count) {
    if (count == 0) {
      return;
    }
    if (count > 24) {
      final hiCount = count - 16;
      writeBits((value >>> 16) & ((1 << hiCount) - 1), hiCount);
      writeBits(value & 0xffff, 16);
      return;
    }
    _bitBuf = ((_bitBuf << count) | (value & ((1 << count) - 1))) & 0xffffffff;
    _bitCount += count;
    while (_bitCount >= 8) {
      _bitCount -= 8;
      _writer.writeUint8((_bitBuf >>> _bitCount) & 0xff);
    }
    _bitBuf &= (1 << _bitCount) - 1;
  }

  /// Pads the final byte with zero bits if not byte-aligned.
  void alignToByte() {
    if (_bitCount > 0) {
      _writer.writeUint8((_bitBuf << (8 - _bitCount)) & 0xff);
      _bitBuf = 0;
      _bitCount = 0;
    }
  }

  /// Flushes remaining bits and returns the encoded [Uint8List].
  Uint8List toBytes() {
    alignToByte();
    return _writer.toBytes();
  }
}

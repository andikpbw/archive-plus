import 'dart:typed_data';

import '../core/archive_exceptions.dart';

/// Performs Web/JS-safe unsigned 32-bit multiplication.
///
/// On Dart web targets, `int` values are IEEE 754 doubles with 53-bit integer
/// precision, so multiplying two arbitrary 32-bit unsigned integers directly
/// can lose low bits. Splitting into 16-bit halves guarantees bit-identical
/// results across VM, JavaScript, and WebAssembly.
@pragma('vm:prefer-inline')
int imul32(int a, int b) {
  final aLo = a & 0xffff;
  final aHi = (a >>> 16) & 0xffff;
  final bLo = b & 0xffff;
  final bHi = (b >>> 16) & 0xffff;
  return ((aLo * bLo) + (((aHi * bLo + aLo * bHi) & 0xffff) << 16)) &
      0xffffffff;
}

/// Unsigned 32-bit rotate-left.
@pragma('vm:prefer-inline')
int rotl32(int value, int shift) {
  final v = value & 0xffffffff;
  return ((v << shift) | (v >>> (32 - shift))) & 0xffffffff;
}

/// Unsigned 32-bit rotate-right.
@pragma('vm:prefer-inline')
int rotr32(int value, int shift) {
  final v = value & 0xffffffff;
  return ((v >>> shift) | (v << (32 - shift))) & 0xffffffff;
}

/// Converts any `List<int>` into a [Uint8List], returning the original view
/// without copying when it is already a [Uint8List].
@pragma('vm:prefer-inline')
Uint8List asUint8List(List<int> bytes) {
  if (bytes is Uint8List) {
    return bytes;
  }
  return Uint8List.fromList(bytes);
}

/// Sequential and random-access binary reader over a [Uint8List].
final class ByteReader {
  /// Creates a [ByteReader] over [bytes], starting at [offset] and bounded by
  /// [end] (defaults to `bytes.length`).
  ByteReader(List<int> bytes, {int offset = 0, int? end})
    : _bytes = asUint8List(bytes),
      _offset = offset,
      _end = end ?? bytes.length {
    if (offset < 0 || _end < offset || _end > _bytes.length) {
      throw ArchiveFormatException(
        'Invalid byte range [$offset, $_end) for buffer of length ${_bytes.length}.',
        offset: offset,
      );
    }
  }

  final Uint8List _bytes;
  int _offset;
  final int _end;

  /// Underlying byte buffer.
  Uint8List get buffer => _bytes;

  /// Current read cursor position.
  int get offset => _offset;

  /// Sets the current read cursor position.
  set offset(int value) {
    if (value < 0 || value > _end) {
      throw ArchiveFormatException(
        'Seek offset $value out of bounds [0, $_end].',
        offset: value,
      );
    }
    _offset = value;
  }

  /// Exclusive upper bound of readable bytes.
  int get end => _end;

  /// Number of unread bytes remaining.
  int get remaining => _end - _offset;

  /// Whether the cursor has reached the end of the buffer.
  bool get isEof => _offset >= _end;

  void _require(int count) {
    if (_offset + count > _end) {
      throw ArchiveFormatException(
        'Unexpected end of input: needed $count bytes, only $remaining remaining.',
        offset: _offset,
      );
    }
  }

  /// Advances the cursor by [count] bytes.
  void skip(int count) {
    if (count < 0 || _offset + count > _end) {
      throw ArchiveFormatException(
        'Cannot skip $count bytes from offset $_offset (end: $_end).',
        offset: _offset,
      );
    }
    _offset += count;
  }

  /// Reads one unsigned 8-bit integer.
  @pragma('vm:prefer-inline')
  int readUint8() {
    _require(1);
    return _bytes[_offset++];
  }

  /// Reads one unsigned 16-bit little-endian integer.
  @pragma('vm:prefer-inline')
  int readUint16LE() {
    _require(2);
    final v = _bytes[_offset] | (_bytes[_offset + 1] << 8);
    _offset += 2;
    return v;
  }

  /// Reads one unsigned 16-bit big-endian integer.
  @pragma('vm:prefer-inline')
  int readUint16BE() {
    _require(2);
    final v = (_bytes[_offset] << 8) | _bytes[_offset + 1];
    _offset += 2;
    return v;
  }

  /// Reads one unsigned 32-bit little-endian integer.
  @pragma('vm:prefer-inline')
  int readUint32LE() {
    _require(4);
    final v =
        _bytes[_offset] |
        (_bytes[_offset + 1] << 8) |
        (_bytes[_offset + 2] << 16) |
        (_bytes[_offset + 3] << 24);
    _offset += 4;
    return v & 0xffffffff;
  }

  /// Reads one unsigned 32-bit big-endian integer.
  @pragma('vm:prefer-inline')
  int readUint32BE() {
    _require(4);
    final v =
        (_bytes[_offset] << 24) |
        (_bytes[_offset + 1] << 16) |
        (_bytes[_offset + 2] << 8) |
        _bytes[_offset + 3];
    _offset += 4;
    return v & 0xffffffff;
  }

  /// Reads an unsigned 64-bit little-endian integer in a Web/JS-safe manner.
  ///
  /// Throws [ArchiveFormatException] if the value exceeds 53-bit safe integer
  /// precision (`0x1fffffffffffff`).
  int readUint64LE() {
    final lo = readUint32LE();
    final hi = readUint32LE();
    if (hi > 0x1fffff) {
      throw ArchiveFormatException(
        '64-bit integer exceeds safe 53-bit precision.',
        offset: _offset - 8,
      );
    }
    return hi * 0x100000000 + lo;
  }

  /// Reads [count] bytes as a zero-copy sublist view.
  Uint8List readBytesView(int count) {
    if (count < 0) {
      throw ArchiveFormatException(
        'Negative read length: $count.',
        offset: _offset,
      );
    }
    _require(count);
    final view = Uint8List.sublistView(_bytes, _offset, _offset + count);
    _offset += count;
    return view;
  }

  /// Reads [count] bytes as an independent copy.
  Uint8List readBytesCopy(int count) {
    final view = readBytesView(count);
    return Uint8List.fromList(view);
  }

  /// Reads a null-terminated byte slice (for GZIP headers, etc.).
  Uint8List readNullTerminatedBytes() {
    final start = _offset;
    while (_offset < _end && _bytes[_offset] != 0) {
      _offset++;
    }
    if (_offset >= _end) {
      throw ArchiveFormatException(
        'Unterminated null-delimited string.',
        offset: start,
      );
    }
    final result = Uint8List.sublistView(_bytes, start, _offset);
    _offset++; // consume NUL
    return result;
  }
}

/// Growable binary writer backed by a single contiguous [Uint8List].
final class ByteWriter {
  /// Creates a [ByteWriter] with the given [initialCapacity].
  ByteWriter([int initialCapacity = 256])
    : _buffer = Uint8List(initialCapacity < 16 ? 16 : initialCapacity);

  Uint8List _buffer;
  int _length = 0;

  /// Current number of written bytes.
  int get length => _length;

  void _ensureCapacity(int additional) {
    final required = _length + additional;
    if (required <= _buffer.length) {
      return;
    }
    var newCap = _buffer.length * 2;
    while (newCap < required) {
      newCap *= 2;
    }
    final next = Uint8List(newCap);
    next.setRange(0, _length, _buffer);
    _buffer = next;
  }

  /// Writes a single byte.
  @pragma('vm:prefer-inline')
  void writeUint8(int value) {
    _ensureCapacity(1);
    _buffer[_length++] = value & 0xff;
  }

  /// Writes a 16-bit little-endian unsigned integer.
  @pragma('vm:prefer-inline')
  void writeUint16LE(int value) {
    _ensureCapacity(2);
    _buffer[_length++] = value & 0xff;
    _buffer[_length++] = (value >>> 8) & 0xff;
  }

  /// Writes a 16-bit big-endian unsigned integer.
  @pragma('vm:prefer-inline')
  void writeUint16BE(int value) {
    _ensureCapacity(2);
    _buffer[_length++] = (value >>> 8) & 0xff;
    _buffer[_length++] = value & 0xff;
  }

  /// Writes a 32-bit little-endian unsigned integer.
  @pragma('vm:prefer-inline')
  void writeUint32LE(int value) {
    _ensureCapacity(4);
    _buffer[_length++] = value & 0xff;
    _buffer[_length++] = (value >>> 8) & 0xff;
    _buffer[_length++] = (value >>> 16) & 0xff;
    _buffer[_length++] = (value >>> 24) & 0xff;
  }

  /// Writes a 32-bit big-endian unsigned integer.
  @pragma('vm:prefer-inline')
  void writeUint32BE(int value) {
    _ensureCapacity(4);
    _buffer[_length++] = (value >>> 24) & 0xff;
    _buffer[_length++] = (value >>> 16) & 0xff;
    _buffer[_length++] = (value >>> 8) & 0xff;
    _buffer[_length++] = value & 0xff;
  }

  /// Writes a 64-bit little-endian unsigned integer (Web/JS safe).
  void writeUint64LE(int value) {
    final lo = value & 0xffffffff;
    final hi = (value - lo) ~/ 0x100000000;
    writeUint32LE(lo);
    writeUint32LE(hi);
  }

  /// Appends all bytes from [bytes], or the slice `[start, end)`.
  void writeBytes(List<int> bytes, [int start = 0, int? end]) {
    final actualEnd = end ?? bytes.length;
    final count = actualEnd - start;
    if (count <= 0) {
      return;
    }
    _ensureCapacity(count);
    _buffer.setRange(_length, _length + count, bytes, start);
    _length += count;
  }

  /// Appends [count] zero bytes.
  void writeZeros(int count) {
    if (count <= 0) {
      return;
    }
    _ensureCapacity(count);
    _buffer.fillRange(_length, _length + count, 0);
    _length += count;
  }

  /// Overwrites a 32-bit little-endian integer at [position].
  void setUint32LEAt(int position, int value) {
    _buffer[position] = value & 0xff;
    _buffer[position + 1] = (value >>> 8) & 0xff;
    _buffer[position + 2] = (value >>> 16) & 0xff;
    _buffer[position + 3] = (value >>> 24) & 0xff;
  }

  /// Returns a freshly sized [Uint8List] containing all written bytes.
  Uint8List toBytes() {
    final out = Uint8List(_length);
    out.setRange(0, _length, _buffer);
    return out;
  }

  /// Returns a zero-copy view over the currently written bytes.
  Uint8List toBytesView() => Uint8List.sublistView(_buffer, 0, _length);
}

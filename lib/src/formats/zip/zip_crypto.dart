import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import '../../core/archive_exceptions.dart';
import '../../util/byte_buffer.dart';

/// Traditional PKWARE ZipCrypto stream cipher implementation (APPNOTE 6.1).
///
/// Uses Web/JS-safe 32-bit unsigned arithmetic ([imul32]) so encryption and
/// decryption produce identical byte streams on VM, JS, and WebAssembly.
final class ZipCrypto {
  /// Creates a [ZipCrypto] cipher initialized with [password].
  ZipCrypto(String password) {
    final passBytes = utf8.encode(password);
    for (final b in passBytes) {
      _updateKeys(b);
    }
  }

  static final Uint32List _crcTable = _buildCrcTable();

  static Uint32List _buildCrcTable() {
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

  int _key0 = 0x12345678;
  int _key1 = 0x23456789;
  int _key2 = 0x34567890;

  @pragma('vm:prefer-inline')
  static int _crc32Byte(int crc, int byte) {
    return ((crc >>> 8) ^ _crcTable[(crc ^ byte) & 0xff]) & 0xffffffff;
  }

  @pragma('vm:prefer-inline')
  void _updateKeys(int plainByte) {
    _key0 = _crc32Byte(_key0, plainByte & 0xff);
    _key1 = (_key1 + (_key0 & 0xff)) & 0xffffffff;
    _key1 = (imul32(_key1, 134775813) + 1) & 0xffffffff;
    _key2 = _crc32Byte(_key2, (_key1 >>> 24) & 0xff);
  }

  @pragma('vm:prefer-inline')
  int _decryptByte() {
    final temp = (_key2 | 2) & 0xffff;
    return ((temp * (temp ^ 1)) >>> 8) & 0xff;
  }

  /// Encrypts [plainData] prepended with the standard 12-byte ZipCrypto header
  /// validated using [checkByte] (`(crc32 >>> 24) & 0xff`).
  static Uint8List encrypt(
    Uint8List plainData, {
    required String password,
    required int checkByte,
    Random? random,
  }) {
    final rng = random ?? _secureRandomOrFallback();
    final cipher = ZipCrypto(password);
    final out = Uint8List(12 + plainData.length);

    // 11 random salt bytes + 1 check byte.
    for (var i = 0; i < 11; i++) {
      final plain = rng.nextInt(256);
      final k = cipher._decryptByte();
      cipher._updateKeys(plain);
      out[i] = plain ^ k;
    }
    {
      final plain = checkByte & 0xff;
      final k = cipher._decryptByte();
      cipher._updateKeys(plain);
      out[11] = plain ^ k;
    }

    for (var i = 0; i < plainData.length; i++) {
      final plain = plainData[i];
      final k = cipher._decryptByte();
      cipher._updateKeys(plain);
      out[12 + i] = plain ^ k;
    }

    return out;
  }

  /// Decrypts [encryptedData] (which begins with the 12-byte ZipCrypto header)
  /// and validates the check byte against [crcCheckByte] (or [dosTimeCheckByte]
  /// when a data descriptor is used).
  static Uint8List decrypt(
    Uint8List encryptedData, {
    required String password,
    required int crcCheckByte,
    required int dosTimeCheckByte,
    required bool hasDataDescriptor,
    String? entryName,
  }) {
    if (encryptedData.length < 12) {
      throw ArchiveFormatException(
        'Encrypted ZIP payload is shorter than the 12-byte ZipCrypto header.',
        entryName: entryName,
      );
    }

    final cipher = ZipCrypto(password);
    var lastHeaderByte = 0;
    for (var i = 0; i < 12; i++) {
      final plain = encryptedData[i] ^ cipher._decryptByte();
      cipher._updateKeys(plain);
      lastHeaderByte = plain;
    }

    final validCheck = hasDataDescriptor
        ? (lastHeaderByte == (dosTimeCheckByte & 0xff) ||
              lastHeaderByte == (crcCheckByte & 0xff))
        : (lastHeaderByte == (crcCheckByte & 0xff));
    if (!validCheck) {
      throw ArchivePasswordException(
        'Incorrect password for encrypted ZIP entry.',
        entryName: entryName,
      );
    }

    final payloadLen = encryptedData.length - 12;
    final out = Uint8List(payloadLen);
    for (var i = 0; i < payloadLen; i++) {
      final plain = encryptedData[12 + i] ^ cipher._decryptByte();
      cipher._updateKeys(plain);
      out[i] = plain;
    }
    return out;
  }

  static Random _secureRandomOrFallback() {
    try {
      return Random.secure();
    } on UnsupportedError {
      return Random();
    }
  }
}

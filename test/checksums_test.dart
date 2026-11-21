import 'dart:convert';
import 'dart:typed_data';

import 'package:archive_plus/archive_plus.dart';
import 'package:test/test.dart';

void main() {
  group('Checksums', () {
    test('CRC-32 IEEE standard test vectors', () {
      expect(Crc32.compute(const <int>[]), 0x00000000);
      expect(Crc32.compute(ascii.encode('123456789')), 0xcbf43926);
      expect(
        Crc32.compute(
          ascii.encode('The quick brown fox jumps over the lazy dog'),
        ),
        0x414fa339,
      );

      final sink = Crc32.sink()
        ..add(ascii.encode('1234'))
        ..add(ascii.encode('56789'));
      expect(sink.value, 0xcbf43926);
      sink.reset();
      expect(sink.value, 0);
    });

    test('Adler-32 RFC 1950 test vectors', () {
      expect(Adler32.compute(const <int>[]), 0x00000001);
      expect(Adler32.compute(ascii.encode('Wikipedia')), 0x11e60398);
      expect(Adler32.compute(ascii.encode('123456789')), 0x091e01de);

      // Multi-chunk > 5552 bytes (deferred modulo boundary).
      final large = Uint8List.fromList(
        List<int>.generate(20000, (i) => i & 0xff),
      );
      final direct = Adler32.compute(large);
      final sink = Adler32.sink()
        ..add(large, 0, 7777)
        ..add(large, 7777, 15000)
        ..add(large, 15000, large.length);
      expect(sink.value, direct);
    });

    test('BZip2 CRC-32 test vectors and combine', () {
      expect(BZip2Crc32.compute(const <int>[]), 0x00000000);
      // Standard MSB-first MPEG-2 / BZip2 inverted CRC for "123456789":
      expect(BZip2Crc32.compute(ascii.encode('123456789')), 0xfc891918);
      expect(BZip2Crc32.combine(0, 0x12345678), 0x12345678);
      expect(BZip2Crc32.combine(0x80000000, 0), 0x00000001);
    });

    test('XXH32 official reference test vectors', () {
      // Official xxHash32 vectors (seed = 0):
      expect(Xxh32.compute(const <int>[]), 0x02cc5d05);
      expect(Xxh32.compute(ascii.encode('a')), 0x550d7456);
      expect(Xxh32.compute(ascii.encode('abc')), 0x32d153ff);
      expect(Xxh32.compute(ascii.encode('abcd')), 0xa3643705);
      expect(Xxh32.compute(ascii.encode('12345678901234567890')), 0x2d0c3d1b);
      expect(
        Xxh32.compute(
          ascii.encode('The quick brown fox jumps over the lazy dog'),
        ),
        0xe85ea4de,
      );
      expect(
        Xxh32.compute(ascii.encode('Nobody inspects the spammish repetition')),
        0xe2293b2f,
      );
      // Non-zero seed vector for empty buffer (seed = 0x9e3779b1):
      expect(Xxh32.compute(const <int>[], seed: 0x9e3779b1), 0x36b78ae7);
    });
  });
}

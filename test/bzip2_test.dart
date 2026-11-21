import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:archive_plus/archive_plus.dart';
import 'package:test/test.dart';

Uint8List _pseudoRandom(int length, int seed) {
  final rng = Random(seed);
  return Uint8List.fromList(
    List<int>.generate(length, (_) => rng.nextInt(256)),
  );
}

void main() {
  group('BZip2', () {
    test(
      'encodes and decodes empty stream (exact 14-byte standard stream)',
      () {
        final bz = ArchivePlus.bzip2(Uint8List(0));
        expect(bz.length, 14);
        expect(ascii.decode(bz.sublist(0, 4)), 'BZh9');
        expect(ArchivePlus.bunzip2(bz), isEmpty);
      },
    );

    test(
      'handles single byte and RLE1 boundary run lengths (4, 255, 256, 1000)',
      () {
        final cases = <String, Uint8List>{
          '1 byte': Uint8List.fromList(<int>[0x42]),
          '3 identical': Uint8List.fromList(<int>[0x61, 0x61, 0x61]),
          '4 identical': Uint8List.fromList(<int>[0x61, 0x61, 0x61, 0x61]),
          '5 identical': Uint8List.fromList(<int>[
            0x61,
            0x61,
            0x61,
            0x61,
            0x61,
          ]),
          '255 identical': Uint8List.fromList(List<int>.filled(255, 0x7a)),
          '256 identical': Uint8List.fromList(List<int>.filled(256, 0x7a)),
          '260 identical': Uint8List.fromList(List<int>.filled(260, 0x7a)),
          '1000 identical': Uint8List.fromList(List<int>.filled(1000, 0x00)),
          'periodic ab': utf8.encode('ab' * 500),
          'periodic abc': utf8.encode('abc' * 333),
          'all 256 bytes': Uint8List.fromList(
            List<int>.generate(256, (i) => i),
          ),
        };

        for (final entry in cases.entries) {
          final encoded = ArchivePlus.bzip2(entry.value);
          final decoded = ArchivePlus.bunzip2(encoded);
          expect(decoded, equals(entry.value), reason: entry.key);
        }
      },
    );

    test('handles multi-block compression and high-entropy random data', () {
      // > 220 KiB at blockSize100k = 1 forces 3 separate BZip2 blocks.
      final data = Uint8List.fromList(<int>[
        ...utf8.encode('BZip2 multi-block compression test! ' * 2500),
        ..._pseudoRandom(140000, 2026),
      ]);
      final encoded = ArchivePlus.bzip2(
        data,
        options: const BZip2Options(blockSize100k: 1),
      );
      final decoded = ArchivePlus.bunzip2(encoded);
      expect(decoded, equals(data));
    });

    test('decodes concatenated multi-stream BZip2 payloads', () {
      final s1 = ArchivePlus.bzip2(utf8.encode('Stream One — '));
      final s2 = ArchivePlus.bzip2(utf8.encode('Stream Two!'));
      final combined = Uint8List.fromList(<int>[...s1, ...s2]);
      expect(
        utf8.decode(ArchivePlus.bunzip2(combined)),
        'Stream One — Stream Two!',
      );
    });

    test('detects BZip2 CRC tampering and supports dart:convert codec', () {
      final raw = utf8.encode('Verify BZip2 integrity checks ' * 100);
      const codec = BZip2PlusCodec();
      final encoded = Uint8List.fromList(codec.encode(raw));
      expect(codec.decode(encoded), equals(raw));

      // Flip a bit in the trailing combined CRC.
      encoded[encoded.length - 1] ^= 0x80;
      expect(
        () => codec.decode(encoded),
        throwsA(isA<ArchiveChecksumException>()),
      );
    });
  });
}

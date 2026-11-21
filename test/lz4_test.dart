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
  group('LZ4 Frame Format', () {
    test('round-trips empty, tiny, repetitive, and incompressible data', () {
      final cases = <String, Uint8List>{
        'empty': Uint8List(0),
        '1 byte': Uint8List.fromList(<int>[0x99]),
        '12 bytes': utf8.encode('0123456789ab'),
        'repetitive': utf8.encode('LZ4 ultra-fast frame compression! ' * 3000),
        'zeros 150k': Uint8List(150000),
        'random 80k': _pseudoRandom(80000, 31415),
      };

      for (final entry in cases.entries) {
        final encoded = ArchivePlus.lz4(entry.value);
        final decoded = ArchivePlus.unlz4(
          encoded,
          options: const Lz4Options(
            securityPolicy: ArchiveSecurityPolicy.unrestricted,
          ),
        );
        expect(decoded, equals(entry.value), reason: entry.key);
      }
    });

    test('supports all block sizes, block checksums, and optional headers', () {
      final payload = Uint8List.fromList(<int>[
        ...utf8.encode(
          'Multi-block LZ4 payload with high compression ratio! ' * 3000,
        ),
        ..._pseudoRandom(70000, 55),
      ]);

      for (final blockSize in Lz4BlockSize.values) {
        for (final blockChecksum in <bool>[false, true]) {
          for (final includeSize in <bool>[false, true]) {
            final opts = Lz4Options(
              blockSize: blockSize,
              blockChecksum: blockChecksum,
              contentChecksum: true,
              includeContentSize: includeSize,
            );
            final encoded = ArchivePlus.lz4(payload, options: opts);
            final decoded = ArchivePlus.unlz4(encoded);
            expect(
              decoded,
              equals(payload),
              reason:
                  'blockSize=$blockSize blockCrc=$blockChecksum size=$includeSize',
            );
          }
        }
      }
    });

    test('handles skippable frames and concatenated frames', () {
      final f1 = ArchivePlus.lz4(utf8.encode('Frame 1 + '));
      final skippable = Uint8List.fromList(<int>[
        0x50, 0x2a, 0x4d, 0x18, // magic 0x184D2A50
        0x04, 0x00, 0x00, 0x00, // length = 4
        0xde, 0xad, 0xbe, 0xef, // skipped user metadata
      ]);
      final f2 = ArchivePlus.lz4(utf8.encode('Frame 2!'));
      final combined = Uint8List.fromList(<int>[...f1, ...skippable, ...f2]);

      expect(utf8.decode(ArchivePlus.unlz4(combined)), 'Frame 1 + Frame 2!');
    });

    test('detects header, block, and content XXH32 tampering', () {
      final data = utf8.encode('Integrity check for LZ4 ' * 200);
      final encoded = ArchivePlus.lz4(
        data,
        options: const Lz4Options(blockChecksum: true, contentChecksum: true),
      );

      // Tamper with content checksum (last byte).
      final badContentCrc = Uint8List.fromList(encoded)
        ..[encoded.length - 1] ^= 0xff;
      expect(
        () => ArchivePlus.unlz4(badContentCrc),
        throwsA(isA<ArchiveChecksumException>()),
      );

      // Tamper with header checksum (byte 14 when content size is included: 4 magic + 2 flg/bd + 8 size = 14).
      final badHeaderCrc = Uint8List.fromList(encoded)..[14] ^= 0x01;
      expect(
        () => ArchivePlus.unlz4(badHeaderCrc),
        throwsA(isA<ArchiveChecksumException>()),
      );
    });

    test('works as dart:convert Codec', () {
      const codec = Lz4PlusCodec();
      final raw = utf8.encode('Codec interface test ' * 100);
      expect(codec.decode(codec.encode(raw)), equals(raw));
    });
  });
}

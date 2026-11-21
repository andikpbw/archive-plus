import 'dart:convert';
import 'dart:typed_data';

import 'package:archive_plus/archive_plus.dart';
import 'package:test/test.dart';

final class _ReverseRleCodec implements ArchiveCompressionCodec {
  @override
  String get name => 'reverse-custom';

  @override
  Uint8List compress(Uint8List input) =>
      Uint8List.fromList(input.reversed.toList());

  @override
  Uint8List decompress(
    Uint8List input, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) => Uint8List.fromList(input.reversed.toList());
}

void main() {
  group('Security Guards (Zip-Slip & Zip-Bomb)', () {
    test('blocks Zip-Slip traversal paths in ZIP and TAR', () {
      final maliciousPaths = <String>[
        '../escape.txt',
        'nested/../../escape.txt',
        '/etc/passwd',
        r'C:\Windows\System32\evil.dll',
        'safe/file\u0000.txt',
      ];

      for (final badPath in maliciousPaths) {
        expect(
          () => PathSanitizer.sanitize(badPath),
          throwsA(
            isA<ArchiveSecurityException>().having(
              (e) => e.violation,
              'violation',
              ArchiveSecurityViolation.pathTraversal,
            ),
          ),
          reason: badPath,
        );
      }

      // Craft a real ZIP with a traversal entry and verify ZipDecoder blocks it.
      final evilZip = ArchivePlus.zip(
        Archive(
          entries: <ArchiveEntry>[ArchiveEntry.text('../pwn.txt', 'evil')],
        ),
      );
      expect(
        () => ArchivePlus.unzip(evilZip),
        throwsA(
          isA<ArchiveSecurityException>().having(
            (e) => e.violation,
            'violation',
            ArchiveSecurityViolation.pathTraversal,
          ),
        ),
      );

      // Craft a real TAR with a traversal entry and verify TarDecoder blocks it.
      final evilTar = ArchivePlus.tar(
        Archive(
          entries: <ArchiveEntry>[ArchiveEntry.text('../../pwn.txt', 'evil')],
        ),
      );
      expect(
        () => ArchivePlus.untar(evilTar),
        throwsA(
          isA<ArchiveSecurityException>().having(
            (e) => e.violation,
            'violation',
            ArchiveSecurityViolation.pathTraversal,
          ),
        ),
      );
    });

    test('blocks Zip-Bomb high compression ratio and size limits', () {
      // 1.5 MiB of zeroes compresses to ~1.5 KiB (~1000x ratio!).
      final bombPayload = Uint8List(1500 * 1024);
      final bombZip = ArchivePlus.builder()
          .addBytes('bomb.bin', bombPayload)
          .encodeZip(
            options: const ZipEncodeOptions(level: CompressionLevel.best),
          );

      expect(
        () => ArchivePlus.unzip(
          bombZip,
          options: const ZipDecodeOptions(
            securityPolicy: ArchiveSecurityPolicy.strict,
          ),
        ),
        throwsA(
          isA<ArchiveSecurityException>().having(
            (e) => e.violation,
            'violation',
            ArchiveSecurityViolation.compressionRatioExceeded,
          ),
        ),
      );

      // Entry size limit enforcement.
      expect(
        () => ArchivePlus.unzip(
          bombZip,
          options: const ZipDecodeOptions(
            securityPolicy: ArchiveSecurityPolicy(
              maxEntrySize: 512 * 1024,
              maxCompressionRatio: null,
            ),
          ),
        ),
        throwsA(
          isA<ArchiveSecurityException>().having(
            (e) => e.violation,
            'violation',
            ArchiveSecurityViolation.entrySizeLimitExceeded,
          ),
        ),
      );

      // Entry count limit enforcement.
      final manyZip = ArchivePlus.builder()
        ..addText('a.txt', '1')
        ..addText('b.txt', '2')
        ..addText('c.txt', '3');
      expect(
        () => ArchivePlus.unzip(
          manyZip.encodeZip(),
          options: const ZipDecodeOptions(
            securityPolicy: ArchiveSecurityPolicy(maxEntryCount: 2),
          ),
        ),
        throwsA(
          isA<ArchiveSecurityException>().having(
            (e) => e.violation,
            'violation',
            ArchiveSecurityViolation.entryCountLimitExceeded,
          ),
        ),
      );
    });
  });

  group(
    'Modern Features (Diff, Stats, Filter, CodecRegistry, Sealed Exceptions)',
    () {
      test('Archive.diff and Archive.stats accurately summarize changes', () {
        final v1 = ArchivePlus.builder()
            .addText('README.md', 'v1')
            .addText('unchanged.txt', 'same')
            .addText('removed.txt', 'bye')
            .build();

        final v2 = ArchivePlus.builder()
            .addText('README.md', 'v2 updated')
            .addText('unchanged.txt', 'same')
            .addText('added.txt', 'hello')
            .build();

        final diff = v1.diff(v2);
        expect(diff.hasChanges, isTrue);
        expect(diff.added.map((e) => e.name), equals(<String>['added.txt']));
        expect(
          diff.removed.map((e) => e.name),
          equals(<String>['removed.txt']),
        );
        expect(diff.modified.map((e) => e.name), equals(<String>['README.md']));
        expect(
          diff.unchanged.map((e) => e.name),
          equals(<String>['unchanged.txt']),
        );

        final zipBytes = ArchivePlus.zip(v2);
        final decoded = ArchivePlus.unzip(zipBytes);
        expect(decoded.stats.fileCount, 3);
        expect(decoded.stats.totalUncompressedBytes, greaterThan(0));
      });

      test('ArchiveCodecRegistry supports built-in and custom codecs', () {
        final registry = ArchivePlus.defaultRegistry();
        expect(
          registry.compressionNames,
          containsAll(<String>['gzip', 'zlib', 'bzip2', 'lz4']),
        );
        expect(
          registry.formatNames,
          containsAll(<String>['zip', 'tar', 'tar.gz', 'tar.bz2']),
        );

        registry.registerCompression(_ReverseRleCodec());
        final custom = registry.compression('reverse-custom')!;
        final raw = utf8.encode('custom codec');
        final enc = custom.compress(raw);
        expect(utf8.decode(enc), 'cedoc motsuc');
        expect(custom.decompress(enc), equals(raw));

        final zipBytes = registry
            .format('zip')!
            .encode(ArchivePlus.builder().addText('hi.txt', 'ok').build());
        expect(registry.detectFormat(zipBytes)?.name, 'zip');
      });

      test('exhaustive Dart 3 switch over sealed ArchiveException', () {
        String classify(ArchiveException ex) {
          return switch (ex) {
            ArchiveFormatException() => 'format',
            ArchiveChecksumException() => 'checksum',
            ArchiveSecurityException() => 'security',
            ArchivePasswordException() => 'password',
            ArchiveCancelledException() => 'cancelled',
            ArchiveIoException() => 'io',
          };
        }

        expect(classify(const ArchiveFormatException('bad')), 'format');
        expect(
          classify(
            const ArchiveChecksumException('crc', expected: 1, actual: 2),
          ),
          'checksum',
        );
        expect(
          classify(
            const ArchiveSecurityException(
              'slip',
              violation: ArchiveSecurityViolation.pathTraversal,
            ),
          ),
          'security',
        );
        expect(classify(const ArchivePasswordException('pw')), 'password');
        expect(classify(const ArchiveCancelledException()), 'cancelled');
        expect(classify(const ArchiveIoException('io')), 'io');
      });
    },
  );
}

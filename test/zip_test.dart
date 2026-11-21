import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:archive_plus/archive_plus.dart';
import 'package:test/test.dart';

void main() {
  group('ZIP Encoder & Decoder', () {
    test(
      'round-trips Store, DEFLATE, BZip2, directories, UTF-8, comments & timestamps',
      () {
        final mtime = DateTime.utc(2026, 6, 15, 14, 22, 36);
        final randomBytes = Uint8List.fromList(
          List<int>.generate(4096, (_) => Random(7).nextInt(256)),
        );

        final zipBytes = ArchivePlus.builder()
            .addText(
              'docs/README.md',
              '# ArchivePlus 🚀\n' * 100,
              modifiedTime: mtime,
              comment: 'Main documentation',
              permissions: 0x1a4,
            )
            .addText(
              'unicode/日本語_Bahasa_🚀.txt',
              'Halo dunia! こんにちは! 🌍\n' * 20,
              modifiedTime: mtime,
              compression: CompressionMethod.bzip2,
            )
            .addBytes(
              'raw/stored.bin',
              randomBytes,
              compression: CompressionMethod.store,
            )
            .addBytes(
              'raw/auto_store_incompressible.bin',
              Uint8List.fromList(
                List<int>.generate(
                  4096,
                  (i) => Random(i * 31 + 5).nextInt(256),
                ),
              ),
              compression: CompressionMethod.deflate,
            )
            .addText('empty.txt', '')
            .addDirectory('empty_dir/', modifiedTime: mtime, permissions: 0x1ed)
            .addSymlink('docs/latest.md', 'README.md')
            .withComment('Created by ArchivePlus 1.0.0')
            .encodeZip(
              options: const ZipEncodeOptions(
                level: CompressionLevel.best,
                autoStoreIfLarger: true,
              ),
            );

        // Zero-decompression Central Directory inspection.
        final summary = ArchivePlus.inspectZip(zipBytes);
        expect(summary.comment, 'Created by ArchivePlus 1.0.0');
        expect(summary.entries.length, 7);
        expect(summary.fileCount, 5);
        expect(summary.directoryCount, 1);
        expect(
          summary.find('raw/auto_store_incompressible.bin')?.compressionMethod,
          CompressionMethod.store,
        );
        expect(
          summary.find('unicode/日本語_Bahasa_🚀.txt')?.compressionMethod,
          CompressionMethod.bzip2,
        );

        // Selective single-entry extraction.
        final single = ArchivePlus.extractZipEntry(
          zipBytes,
          'unicode/日本語_Bahasa_🚀.txt',
        );
        expect(single, isNotNull);
        expect(single!.readAsString(), 'Halo dunia! こんにちは! 🌍\n' * 20);
        expect(
          ArchivePlus.extractZipEntry(zipBytes, 'does/not/exist.txt'),
          isNull,
        );

        // Full decode.
        final decoded = ArchivePlus.unzip(zipBytes);
        expect(decoded.comment, 'Created by ArchivePlus 1.0.0');
        expect(decoded.length, 7);
        expect(
          decoded.find('docs/README.md')!.readAsString(),
          '# ArchivePlus 🚀\n' * 100,
        );
        expect(decoded.find('docs/README.md')!.comment, 'Main documentation');
        expect(decoded.find('docs/README.md')!.modifiedTime, mtime);
        expect(decoded.find('empty.txt')!.bytes, isEmpty);
        expect(decoded.find('empty_dir/')!.isDirectory, isTrue);
        expect(decoded.find('docs/latest.md')!.isSymbolicLink, isTrue);
        expect(decoded.find('docs/latest.md')!.linkTarget, 'README.md');
      },
    );

    test('supports empty ZIP archive', () {
      final zipBytes = ArchivePlus.zip(Archive());
      expect(ArchivePlus.detectFormat(zipBytes), ArchiveFormat.zip);
      final summary = ArchivePlus.inspectZip(zipBytes);
      expect(summary.entries, isEmpty);
      expect(ArchivePlus.unzip(zipBytes), isEmpty);
    });

    test('supports ZIP64 structures cleanly', () {
      final zipBytes = ArchivePlus.builder()
          .addText('big/data.txt', 'ZIP64 payload verification ' * 400)
          .encodeZip(options: const ZipEncodeOptions(forceZip64: true));

      final summary = ArchivePlus.inspectZip(zipBytes);
      expect(summary.isZip64, isTrue);
      expect(summary.entries.length, 1);

      final decoded = ArchivePlus.unzip(zipBytes);
      expect(
        decoded.find('big/data.txt')!.readAsString(),
        'ZIP64 payload verification ' * 400,
      );
    });

    test(
      'supports ZipCrypto password encryption and rejects wrong/missing passwords',
      () {
        final zipBytes = ArchivePlus.builder()
            .addText(
              'secret/notes.txt',
              'Top secret Humanize AI launch plan!' * 20,
            )
            .addDirectory('secret/')
            .encodeZip(
              options: const ZipEncodeOptions(password: 'S3cr3t!Pass'),
            );

        final summary = ArchivePlus.inspectZip(zipBytes);
        expect(summary.encryptedCount, 1);
        expect(summary.find('secret/notes.txt')!.isEncrypted, isTrue);

        // Missing password -> ArchivePasswordException
        expect(
          () => ArchivePlus.unzip(zipBytes),
          throwsA(isA<ArchivePasswordException>()),
        );

        // Wrong password -> ArchivePasswordException
        expect(
          () => ArchivePlus.unzip(
            zipBytes,
            options: const ZipDecodeOptions(password: 'wrong-password'),
          ),
          throwsA(isA<ArchivePasswordException>()),
        );

        // Correct password succeeds
        final unlocked = ArchivePlus.unzip(
          zipBytes,
          options: const ZipDecodeOptions(password: 'S3cr3t!Pass'),
        );
        expect(
          unlocked.find('secret/notes.txt')!.readAsString(),
          'Top secret Humanize AI launch plan!' * 20,
        );
      },
    );

    test('supports progress reporting, filtering, and cancellation', () {
      final builder = ArchivePlus.builder();
      for (var i = 0; i < 10; i++) {
        builder.addText('src/file_$i.dart', 'void fn$i() {}\n' * 50);
        builder.addText('build/tmp_$i.log', 'temporary log $i\n' * 50);
      }

      final phases = <ArchivePhase>[];
      final zipBytes = builder.encodeZip(
        options: ZipEncodeOptions(
          filter: const ArchiveFilter(excludeGlobs: <String>['build/**']),
          onProgress: (p) => phases.add(p.phase),
        ),
      );
      expect(phases, contains(ArchivePhase.compressing));
      expect(phases.last, ArchivePhase.completed);

      final decoded = ArchivePlus.unzip(
        zipBytes,
        options: const ZipDecodeOptions(
          filter: ArchiveFilter(includeGlobs: <String>['src/file_[012].dart']),
        ),
      );
      expect(decoded.length, 3);

      // Cooperative cancellation mid-decoding.
      final cancel = ArchiveCancelToken();
      expect(
        () => ArchivePlus.unzip(
          zipBytes,
          options: ZipDecodeOptions(
            cancelToken: cancel,
            onProgress: (p) {
              if (p.processedEntries >= 2) {
                cancel.cancel('User pressed stop');
              }
            },
          ),
        ),
        throwsA(isA<ArchiveCancelledException>()),
      );
    });

    test('detects corrupted payload via CRC-32 check', () {
      final zipBytes = ArchivePlus.builder()
          .addText(
            'check.txt',
            'Store me uncompressed',
            compression: CompressionMethod.store,
          )
          .encodeZip(
            options: const ZipEncodeOptions(level: CompressionLevel.none),
          );

      // Flip a byte inside the stored payload ("Store me uncompressed").
      final marker = utf8.encode('Store me');
      var payloadIndex = -1;
      for (var i = 0; i <= zipBytes.length - marker.length; i++) {
        var match = true;
        for (var j = 0; j < marker.length; j++) {
          if (zipBytes[i + j] != marker[j]) {
            match = false;
            break;
          }
        }
        if (match) {
          payloadIndex = i;
          break;
        }
      }
      expect(payloadIndex, greaterThan(0));
      zipBytes[payloadIndex] ^= 0xff;

      expect(
        () => ArchivePlus.unzip(zipBytes),
        throwsA(isA<ArchiveChecksumException>()),
      );
    });
  });
}

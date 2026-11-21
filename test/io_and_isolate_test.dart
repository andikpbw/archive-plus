@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:archive_plus/archive_plus_io.dart';
import 'package:test/test.dart';

void main() {
  group('ArchiveFileSystem & ArchiveIsolate (VM / Native)', () {
    late Directory tempRoot;

    setUp(() async {
      tempRoot = await Directory.systemTemp.createTemp('archive_plus_test_');
    });

    tearDown(() async {
      if (await tempRoot.exists()) {
        await tempRoot.delete(recursive: true);
      }
    });

    test('compresses directory to ZIP & TAR.GZ and extracts cleanly', () async {
      final srcDir = Directory('${tempRoot.path}/source');
      await Directory('${srcDir.path}/nested/sub').create(recursive: true);
      await File('${srcDir.path}/hello.txt').writeAsString('Hello from disk!');
      await File(
        '${srcDir.path}/nested/sub/data.json',
      ).writeAsString('{"ok":true}');
      await File('${srcDir.path}/ignored.tmp').writeAsString('skip me');

      final zipPath = '${tempRoot.path}/out/bundle.zip';
      final written = await ArchiveFileSystem.compressDirectoryToZip(
        srcDir.path,
        zipPath,
        directoryFilter: const ArchiveFilter(excludeGlobs: <String>['*.tmp']),
      );
      expect(written, greaterThan(0));
      expect(await File(zipPath).exists(), isTrue);

      final zipOutDir = '${tempRoot.path}/extracted_zip';
      final extractedZip = await ArchiveFileSystem.extractZipFile(
        zipPath,
        zipOutDir,
      );
      expect(extractedZip, contains('hello.txt'));
      expect(extractedZip, contains('nested/sub/data.json'));
      expect(extractedZip, isNot(contains('ignored.tmp')));
      expect(
        await File('$zipOutDir/hello.txt').readAsString(),
        'Hello from disk!',
      );
      expect(
        await File('$zipOutDir/nested/sub/data.json').readAsString(),
        '{"ok":true}',
      );

      // TAR.GZ round-trip & extractAutoFile
      final tgzPath = '${tempRoot.path}/out/bundle.tar.gz';
      await ArchiveFileSystem.compressDirectoryToTarGz(srcDir.path, tgzPath);
      final tgzOutDir = '${tempRoot.path}/extracted_tgz';
      await ArchiveFileSystem.extractAutoFile(tgzPath, tgzOutDir);
      expect(
        await File('$tgzOutDir/hello.txt').readAsString(),
        'Hello from disk!',
      );
    });

    test(
      'blocks symlinks on disk extraction unless explicitly allowed',
      () async {
        final archive = ArchivePlus.builder()
            .addText('real.txt', 'content')
            .addSymlink('link.txt', 'real.txt')
            .build();

        await expectLater(
          ArchiveFileSystem.extractArchive(archive, '${tempRoot.path}/no_sym'),
          throwsA(
            isA<ArchiveSecurityException>().having(
              (e) => e.violation,
              'violation',
              ArchiveSecurityViolation.disallowedSymlink,
            ),
          ),
        );

        final allowed = await ArchiveFileSystem.extractArchive(
          archive,
          '${tempRoot.path}/yes_sym',
          securityPolicy: ArchiveSecurityPolicy.standard.copyWith(
            allowSymlinks: true,
          ),
        );
        expect(allowed, contains('link.txt'));
      },
    );

    test(
      'ArchiveIsolate offloads all codecs cleanly onto background isolates',
      () async {
        final archive = ArchivePlus.builder()
            .addText('doc.txt', 'Background isolate test ' * 500)
            .build();

        final zipBytes = await ArchiveIsolate.encodeZip(
          archive,
          password: 'iso-password',
        );
        final unzipped = await ArchiveIsolate.decodeZip(
          zipBytes,
          password: 'iso-password',
        );
        expect(
          unzipped.find('doc.txt')!.readAsString(),
          'Background isolate test ' * 500,
        );

        final tgzBytes = await ArchiveIsolate.encodeTarGz(archive);
        final untarred = await ArchiveIsolate.decodeTarGz(tgzBytes);
        expect(
          untarred.find('doc.txt')!.readAsString(),
          'Background isolate test ' * 500,
        );

        final raw = utf8.encode(
          'Isolate single-stream compression payload! ' * 300,
        );
        expect(
          await ArchiveIsolate.decompressGzip(
            await ArchiveIsolate.compressGzip(raw),
          ),
          equals(raw),
        );
        expect(
          await ArchiveIsolate.decompressBzip2(
            await ArchiveIsolate.compressBzip2(raw),
          ),
          equals(raw),
        );
        expect(
          await ArchiveIsolate.decompressLz4(
            await ArchiveIsolate.compressLz4(raw),
          ),
          equals(raw),
        );
      },
    );
  });

  group(
    'Real-World Interoperability (Python stdlib zlib/gzip/bz2/zipfile/tarfile)',
    () {
      Future<bool> hasPython3() async {
        try {
          final res = await Process.run('python3', <String>['--version']);
          return res.exitCode == 0;
        } on ProcessException {
          return false;
        }
      }

      test(
        'bidirectional interoperability with Python zlib, gzip, bz2, zipfile, and tarfile',
        () async {
          if (!await hasPython3()) {
            return;
          }

          final tempDir = await Directory.systemTemp.createTemp(
            'archive_plus_interop_',
          );
          try {
            final sampleText =
                'ArchivePlus cross-platform interoperability test 🚀 — Bahasa, 日本語!\n' *
                300;
            final sampleBytes = utf8.encode(sampleText);

            // 1. Write ArchivePlus outputs to disk for Python to verify!
            await File(
              '${tempDir.path}/ap.zlib',
            ).writeAsBytes(ArchivePlus.zlib(sampleBytes));
            await File('${tempDir.path}/ap.gz').writeAsBytes(
              ArchivePlus.gzip(
                sampleBytes,
                options: const GZipOptions(
                  filename: 'sample.txt',
                  includeHeaderCrc: true,
                ),
              ),
            );
            await File(
              '${tempDir.path}/ap.bz2',
            ).writeAsBytes(ArchivePlus.bzip2(sampleBytes));
            await File('${tempDir.path}/ap.zip').writeAsBytes(
              ArchivePlus.builder()
                  .addText('dir/sample.txt', sampleText)
                  .addText(
                    'dir/bz2.txt',
                    sampleText,
                    compression: CompressionMethod.bzip2,
                  )
                  .addDirectory('dir/')
                  .encodeZip(),
            );
            await File('${tempDir.path}/ap.tar.gz').writeAsBytes(
              ArchivePlus.builder()
                  .addText(
                    'very/long/path/${'segment/' * 15}unicode_🚀.txt',
                    sampleText,
                  )
                  .encodeTarGz(),
            );

            // 2. Run Python script to validate ArchivePlus files AND generate Python files!
            const pyScript = r'''
import bz2, gzip, sys, tarfile, zipfile, zlib, os

d = sys.argv[1]
expected = ("ArchivePlus cross-platform interoperability test 🚀 — Bahasa, 日本語!\n" * 300).encode("utf-8")

# Verify ArchivePlus outputs using Python stdlib
assert zlib.decompress(open(f"{d}/ap.zlib", "rb").read()) == expected, "zlib mismatch"
assert gzip.decompress(open(f"{d}/ap.gz", "rb").read()) == expected, "gzip mismatch"
assert bz2.decompress(open(f"{d}/ap.bz2", "rb").read()) == expected, "bz2 mismatch"

with zipfile.ZipFile(f"{d}/ap.zip", "r") as zf:
    assert zf.testzip() is None, "zip CRC failed"
    assert zf.read("dir/sample.txt") == expected, "zip deflate mismatch"
    assert zf.read("dir/bz2.txt") == expected, "zip bz2 mismatch"

with tarfile.open(f"{d}/ap.tar.gz", "r:gz") as tf:
    names = tf.getnames()
    assert len(names) == 1
    assert tf.extractfile(names[0]).read() == expected, "tar.gz mismatch"

# Generate Python stdlib archives for ArchivePlus to decode
open(f"{d}/py.zlib", "wb").write(zlib.compress(expected, level=9))
open(f"{d}/py.gz", "wb").write(gzip.compress(expected, compresslevel=9))
open(f"{d}/py.bz2", "wb").write(bz2.compress(expected, compresslevel=9))

with zipfile.ZipFile(f"{d}/py.zip", "w", compression=zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("from_python/hello.txt", expected)
    zf.writestr("from_python/stored.txt", b"stored payload", compress_type=zipfile.ZIP_STORED)

with tarfile.open(f"{d}/py_gnu.tar", "w", format=tarfile.GNU_FORMAT) as tf:
    import io
    long_name = "gnu/long/path/" + ("deep/" * 25) + "file.txt"
    info = tarfile.TarInfo(name=long_name)
    info.size = len(expected)
    tf.addfile(info, io.BytesIO(expected))

print("PYTHON_INTEROP_OK")
''';

            final res = await Process.run('python3', <String>[
              '-c',
              pyScript,
              tempDir.path,
            ]);
            expect(res.exitCode, 0, reason: 'Python stderr: ${res.stderr}');
            expect((res.stdout as String).trim(), 'PYTHON_INTEROP_OK');

            // 3. Verify ArchivePlus decodes EVERY Python-generated file cleanly!
            expect(
              ArchivePlus.unzlib(
                await File('${tempDir.path}/py.zlib').readAsBytes(),
              ),
              equals(sampleBytes),
            );
            expect(
              ArchivePlus.gunzip(
                await File('${tempDir.path}/py.gz').readAsBytes(),
              ),
              equals(sampleBytes),
            );
            expect(
              ArchivePlus.bunzip2(
                await File('${tempDir.path}/py.bz2').readAsBytes(),
              ),
              equals(sampleBytes),
            );

            final pyZip = ArchivePlus.unzip(
              await File('${tempDir.path}/py.zip').readAsBytes(),
            );
            expect(
              pyZip.find('from_python/hello.txt')!.bytes,
              equals(sampleBytes),
            );
            expect(
              pyZip.find('from_python/stored.txt')!.readAsString(),
              'stored payload',
            );

            final pyTar = ArchivePlus.untar(
              await File('${tempDir.path}/py_gnu.tar').readAsBytes(),
            );
            final expectedLong = 'gnu/long/path/${'deep/' * 25}file.txt';
            expect(pyTar.find(expectedLong)!.bytes, equals(sampleBytes));
          } finally {
            if (await tempDir.exists()) {
              await tempDir.delete(recursive: true);
            }
          }
        },
      );
    },
  );
}

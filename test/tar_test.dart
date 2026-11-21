import 'dart:convert';
import 'dart:typed_data';

import 'package:archive_plus/archive_plus.dart';
import 'package:test/test.dart';

void main() {
  group('TAR, TAR.GZ & TAR.BZ2', () {
    test(
      'round-trips USTAR entries, PAX long paths, Unicode, symlinks & custom metadata',
      () {
        const veryLongPath =
            'very/deeply/nested/directory/structure/that/exceeds/one/hundred/and/fifty/five/'
            'characters/to/verify/posix/pax/extended/header/support/file_name_with_unicode_🚀_日本語.json';
        final mtime = DateTime.utc(2026, 3, 10, 8, 15, 0);

        final tarBytes = ArchivePlus.builder()
            .addText(
              'short.txt',
              'Simple USTAR entry',
              modifiedTime: mtime,
              permissions: 0x1a4,
            )
            .addJson(veryLongPath, <String, Object>{
              'library': 'archive_plus',
              'pax': true,
            }, pretty: true)
            .addDirectory('assets/icons/', permissions: 0x1ed)
            .addSymlink('current', 'short.txt')
            .addEntry(
              ArchiveEntry.text(
                'meta.txt',
                'with custom PAX metadata',
                metadata: const <String, String>{
                  'ARCHIVEPLUS.author': 'Humanize AI',
                },
              ),
            )
            .encodeTar();

        expect(ArchivePlus.detectFormat(tarBytes), ArchiveFormat.tar);

        final decoded = ArchivePlus.untar(tarBytes);
        expect(decoded.length, 5);
        expect(decoded.find('short.txt')!.readAsString(), 'Simple USTAR entry');
        expect(decoded.find('short.txt')!.modifiedTime, mtime);
        expect(decoded.find('short.txt')!.permissions, 0x1a4);
        expect(decoded.find(veryLongPath)!.readAsJson(), <String, Object>{
          'library': 'archive_plus',
          'pax': true,
        });
        expect(decoded.find('assets/icons/')!.isDirectory, isTrue);
        expect(decoded.find('current')!.isSymbolicLink, isTrue);
        expect(decoded.find('current')!.linkTarget, 'short.txt');
        expect(
          decoded.find('meta.txt')!.metadata['ARCHIVEPLUS.author'],
          'Humanize AI',
        );
      },
    );

    test('round-trips TAR.GZ and TAR.BZ2 with auto-format detection', () {
      final archive = ArchivePlus.builder()
          .addText(
            'app/main.dart',
            'void main() => print("ArchivePlus");\n' * 50,
          )
          .addJson('app/config.json', <String, Object>{
            'modern': true,
            'fast': true,
          })
          .build();

      final tgz = ArchivePlus.tarGz(archive);
      final tbz2 = ArchivePlus.tarBz2(archive);

      expect(
        ArchivePlus.detectFormat(tgz, fileName: 'release.tar.gz'),
        ArchiveFormat.tarGz,
      );
      expect(
        ArchivePlus.detectFormat(tbz2, fileName: 'release.tar.bz2'),
        ArchiveFormat.tarBz2,
      );

      // decodeAuto detects inner TAR even WITHOUT a filename hint!
      final autoTgz = ArchivePlus.decodeAuto(tgz);
      expect(autoTgz.length, 2);
      expect(autoTgz.find('app/config.json')!.readAsJson(), <String, Object>{
        'modern': true,
        'fast': true,
      });

      final autoTbz2 = ArchivePlus.decodeAuto(tbz2);
      expect(autoTbz2.length, 2);
      expect(
        autoTbz2.find('app/main.dart')!.readAsString(),
        'void main() => print("ArchivePlus");\n' * 50,
      );
    });

    test('detects TAR header checksum corruption', () {
      final tarBytes = ArchivePlus.builder()
          .addText('ok.txt', 'hello')
          .encodeTar();
      tarBytes[0] ^= 0xff;
      expect(
        () => ArchivePlus.untar(tarBytes),
        throwsA(isA<ArchiveChecksumException>()),
      );
    });

    test('decodes single-file GZIP, BZip2, LZ4, and ZLIB via decodeAuto', () {
      const text = 'Auto-decoded single stream payload!';
      final raw = utf8.encode(text);

      final gzArch = ArchivePlus.decodeAuto(
        ArchivePlus.gzip(
          raw,
          options: const GZipOptions(filename: 'hello.txt'),
        ),
      );
      expect(gzArch.single.name, 'hello.txt');
      expect(gzArch.single.readAsString(), text);

      final bzArch = ArchivePlus.decodeAuto(
        ArchivePlus.bzip2(raw),
        fileName: 'notes.txt.bz2',
      );
      expect(bzArch.single.name, 'notes.txt');
      expect(bzArch.single.readAsString(), text);

      final lz4Arch = ArchivePlus.decodeAuto(
        ArchivePlus.lz4(raw),
        fileName: 'telemetry.log.lz4',
      );
      expect(lz4Arch.single.name, 'telemetry.log');
      expect(lz4Arch.single.readAsString(), text);

      final zlibArch = ArchivePlus.decodeAuto(
        ArchivePlus.zlib(raw),
        fileName: 'blob.bin.zlib',
      );
      expect(zlibArch.single.name, 'blob.bin');
      expect(zlibArch.single.readAsString(), text);

      expect(
        () => ArchivePlus.decodeAuto(Uint8List.fromList(<int>[1, 2, 3, 4])),
        throwsA(isA<ArchiveFormatException>()),
      );
    });
  });
}

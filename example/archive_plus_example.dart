import 'dart:convert';
import 'dart:typed_data';

import 'package:archive_plus/archive_plus.dart';

void main() {
  // 1. Build a multi-file ZIP archive using the fluent ArchiveBuilder API.
  final zipBytes = ArchivePlus.builder()
      .addText(
        'README.md',
        '# ArchivePlus\nModern compression for Dart & Flutter.',
      )
      .addJson('config/app.json', <String, Object>{
        'name': 'archive_plus',
        'zeroDependencies': true,
      }, pretty: true)
      .addBytes('assets/raw.bin', Uint8List.fromList(<int>[1, 2, 3, 4, 5]))
      .addDirectory('logs/')
      .withComment('Built with ArchivePlus')
      .encodeZip(
        options: ZipEncodeOptions(
          level: CompressionLevel.best,
          onProgress: (progress) {
            if (progress.phase == ArchivePhase.completed) {
              print(
                'ZIP encoded: ${progress.totalEntries} entries '
                '(${progress.bytesProcessed} B -> ${progress.compressedBytes} B)',
              );
            }
          },
        ),
      );

  // 2. Inspect ZIP Central Directory with zero decompression overhead.
  final summary = ArchivePlus.inspectZip(zipBytes);
  print(
    'Inspected ZIP: ${summary.fileCount} files, '
    'saved ${summary.savedPercentage.toStringAsFixed(1)}%',
  );

  // 3. Extract a single entry selectively without inflating the rest.
  final configEntry = ArchivePlus.extractZipEntry(zipBytes, 'config/app.json');
  print('Config JSON: ${configEntry?.readAsJson()}');

  // 4. Decode safely with built-in Zip-Slip and Zip-Bomb protection.
  final decoded = ArchivePlus.unzip(
    zipBytes,
    options: const ZipDecodeOptions(
      securityPolicy: ArchiveSecurityPolicy.strict,
    ),
  );
  print('Decoded entries: ${decoded.filePaths.join(', ')}');

  // 5. Auto-detect and decode TAR.GZ, BZip2, GZIP, ZLIB, and LZ4 streams.
  final tarGzBytes = ArchivePlus.tarGz(decoded);
  final detected = ArchivePlus.detectFormat(
    tarGzBytes,
    fileName: 'bundle.tar.gz',
  );
  print('Detected format: ${detected.name}');

  final payload = utf8.encode('Ultra-fast LZ4 Frame compression! ' * 200);
  final lz4Bytes = ArchivePlus.lz4(payload);
  final restored = ArchivePlus.unlz4(lz4Bytes);
  print(
    'LZ4 round-trip: ${payload.length} B -> ${lz4Bytes.length} B '
    '(verified ${restored.length == payload.length})',
  );
}

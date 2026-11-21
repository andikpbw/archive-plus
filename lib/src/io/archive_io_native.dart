import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import '../archive_plus_facade.dart';
import '../core/archive.dart';
import '../core/archive_exceptions.dart';
import '../core/archive_filter.dart';
import '../core/archive_options.dart';
import '../core/archive_progress.dart';
import '../core/archive_security.dart';

/// Native `dart:io` file-system utilities for reading directories into
/// [Archive] instances and securely extracting archives to disk.
final class ArchiveFileSystem {
  ArchiveFileSystem._();

  /// Recursively reads files and directories from [directoryPath] into an
  /// [Archive].
  static Future<Archive> readDirectory(
    String directoryPath, {
    ArchiveFilter? filter,
    bool followLinks = false,
    bool includeEmptyDirectories = true,
    ArchiveProgressCallback? onProgress,
    ArchiveCancelToken? cancelToken,
  }) async {
    cancelToken?.throwIfCancelled();

    final rootDir = Directory(directoryPath);
    if (!await rootDir.exists()) {
      throw ArchiveIoException(
        'Source directory does not exist: "$directoryPath".',
      );
    }

    final resolvedRoot = await rootDir.resolveSymbolicLinks();
    final rootPrefix = resolvedRoot.endsWith(Platform.pathSeparator)
        ? resolvedRoot
        : '$resolvedRoot${Platform.pathSeparator}';

    final entities = await rootDir
        .list(recursive: true, followLinks: followLinks)
        .toList();

    final archive = Archive();
    var processed = 0;
    var totalBytes = 0;

    for (final entity in entities) {
      cancelToken?.throwIfCancelled();

      String entityPath;
      try {
        entityPath = entity is Link
            ? _normalizeNativePath(entity.path)
            : await entity.resolveSymbolicLinks();
      } on FileSystemException {
        entityPath = _normalizeNativePath(entity.path);
      }

      var relative = _relativePath(entityPath, rootPrefix, rootDir.path);
      if (relative.isEmpty) {
        continue;
      }

      if (entity is Directory) {
        if (!includeEmptyDirectories) {
          continue;
        }
        if (!relative.endsWith('/')) {
          relative = '$relative/';
        }
        if (filter != null && !filter.matches(relative, isDirectory: true)) {
          continue;
        }
        final stat = await entity.stat();
        archive.add(
          ArchiveEntry.directory(
            relative,
            modifiedTime: stat.modified.toUtc(),
            permissions: stat.mode & 0xfff,
          ),
        );
      } else if (entity is Link) {
        final target = await entity.target();
        if (filter != null && !filter.matches(relative, isDirectory: false)) {
          continue;
        }
        archive.add(ArchiveEntry.symbolicLink(relative, target));
      } else if (entity is File) {
        final stat = await entity.stat();
        if (filter != null &&
            !filter.matches(relative, size: stat.size, isDirectory: false)) {
          continue;
        }
        final bytes = await entity.readAsBytes();
        totalBytes += bytes.length;
        archive.add(
          ArchiveEntry.file(
            relative,
            bytes,
            modifiedTime: stat.modified.toUtc(),
            permissions: stat.mode & 0xfff,
          ),
        );
      }

      processed++;
      onProgress?.call(
        ArchiveProgress(
          phase: ArchivePhase.reading,
          entryName: relative,
          processedEntries: processed,
          totalEntries: entities.length,
          bytesProcessed: totalBytes,
          totalBytes: totalBytes,
        ),
      );
    }

    onProgress?.call(
      ArchiveProgress(
        phase: ArchivePhase.completed,
        processedEntries: archive.length,
        totalEntries: archive.length,
        bytesProcessed: totalBytes,
        totalBytes: totalBytes,
      ),
    );

    return archive;
  }

  /// Extracts [archive] into [destinationDirectory] while strictly enforcing
  /// [securityPolicy] against Zip-Slip path traversal, symlink escapes, and
  /// size/count limits.
  ///
  /// Returns the list of extracted relative POSIX entry paths.
  static Future<List<String>> extractArchive(
    Archive archive,
    String destinationDirectory, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
    ArchiveFilter? filter,
    bool overwrite = true,
    ArchiveProgressCallback? onProgress,
    ArchiveCancelToken? cancelToken,
  }) async {
    cancelToken?.throwIfCancelled();

    final destDir = Directory(destinationDirectory);
    if (!await destDir.exists()) {
      await destDir.create(recursive: true);
    }
    final canonicalDest = await destDir.resolveSymbolicLinks();
    final canonicalPrefix = canonicalDest.endsWith(Platform.pathSeparator)
        ? canonicalDest
        : '$canonicalDest${Platform.pathSeparator}';

    final entriesToExtract = filter == null
        ? archive.entries
        : archive.entries
              .where(
                (e) => filter.matches(
                  e.name,
                  size: e.size,
                  isDirectory: e.isDirectory,
                ),
              )
              .toList();

    securityPolicy.checkEntryCount(entriesToExtract.length);
    final totalBytes = entriesToExtract.fold<int>(0, (s, e) => s + e.size);

    final extracted = <String>[];
    var writtenBytes = 0;

    for (var i = 0; i < entriesToExtract.length; i++) {
      cancelToken?.throwIfCancelled();
      final entry = entriesToExtract[i];

      final safeName = securityPolicy.sanitizePath(
        entry.name,
        isDirectory: entry.isDirectory,
      );
      if (safeName.isEmpty) {
        continue;
      }

      onProgress?.call(
        ArchiveProgress(
          phase: ArchivePhase.writing,
          entryName: safeName,
          processedEntries: i,
          totalEntries: entriesToExtract.length,
          bytesProcessed: writtenBytes,
          totalBytes: totalBytes,
        ),
      );

      final nativeRel = safeName.replaceAll('/', Platform.pathSeparator);
      final targetPath = '$canonicalPrefix$nativeRel';

      if (entry.isSymbolicLink) {
        if (!securityPolicy.allowSymlinks) {
          throw ArchiveSecurityException(
            'Symbolic link extraction is disallowed by security policy.',
            violation: ArchiveSecurityViolation.disallowedSymlink,
            entryName: safeName,
          );
        }
        final linkTarget = entry.linkTarget ?? '';
        // Ensure symlink target cannot escape destination directory.
        securityPolicy.sanitizePath(linkTarget);
        final link = Link(targetPath);
        await link.parent.create(recursive: true);
        if (await link.exists()) {
          if (!overwrite) {
            continue;
          }
          await link.delete();
        }
        await link.create(linkTarget);
        extracted.add(safeName);
        continue;
      }

      if (entry.isDirectory) {
        final dir = Directory(targetPath);
        await dir.create(recursive: true);
        await _verifyInsideRoot(dir.path, canonicalDest, safeName);
        extracted.add(safeName);
        continue;
      }

      securityPolicy.checkEntrySize(entry.size, entryName: safeName);
      writtenBytes += entry.size;
      securityPolicy.checkTotalSize(writtenBytes, entryName: safeName);

      final file = File(targetPath);
      await file.parent.create(recursive: true);
      await _verifyInsideRoot(file.parent.path, canonicalDest, safeName);

      if (!overwrite && await file.exists()) {
        continue;
      }
      await file.writeAsBytes(entry.bytes, flush: true);
      extracted.add(safeName);
    }

    onProgress?.call(
      ArchiveProgress(
        phase: ArchivePhase.completed,
        processedEntries: entriesToExtract.length,
        totalEntries: entriesToExtract.length,
        bytesProcessed: writtenBytes,
        totalBytes: totalBytes,
      ),
    );

    return extracted;
  }

  /// Compresses [sourceDirectory] directly to a ZIP file at [outputZipPath],
  /// returning the number of bytes written.
  static Future<int> compressDirectoryToZip(
    String sourceDirectory,
    String outputZipPath, {
    ZipEncodeOptions options = const ZipEncodeOptions(),
    ArchiveFilter? directoryFilter,
    bool followLinks = false,
  }) async {
    final archive = await readDirectory(
      sourceDirectory,
      filter: directoryFilter,
      followLinks: followLinks,
      cancelToken: options.cancelToken,
    );
    final zipBytes = ArchivePlus.zip(archive, options: options);
    final outFile = File(outputZipPath);
    await outFile.parent.create(recursive: true);
    await outFile.writeAsBytes(zipBytes, flush: true);
    return zipBytes.length;
  }

  /// Compresses [sourceDirectory] directly to a `.tar.gz` file at [outputPath],
  /// returning the number of bytes written.
  static Future<int> compressDirectoryToTarGz(
    String sourceDirectory,
    String outputPath, {
    TarEncodeOptions tarOptions = const TarEncodeOptions(),
    GZipOptions gzipOptions = const GZipOptions(),
    ArchiveFilter? directoryFilter,
    bool followLinks = false,
  }) async {
    final archive = await readDirectory(
      sourceDirectory,
      filter: directoryFilter,
      followLinks: followLinks,
      cancelToken: tarOptions.cancelToken,
    );
    final tarGzBytes = ArchivePlus.tarGz(
      archive,
      tarOptions: tarOptions,
      gzipOptions: gzipOptions,
    );
    final outFile = File(outputPath);
    await outFile.parent.create(recursive: true);
    await outFile.writeAsBytes(tarGzBytes, flush: true);
    return tarGzBytes.length;
  }

  /// Extracts a ZIP file at [zipPath] into [destinationDirectory], returning
  /// the list of extracted relative entry paths.
  static Future<List<String>> extractZipFile(
    String zipPath,
    String destinationDirectory, {
    ZipDecodeOptions options = const ZipDecodeOptions(),
    bool overwrite = true,
  }) async {
    final file = File(zipPath);
    if (!await file.exists()) {
      throw ArchiveIoException('ZIP file not found: "$zipPath".');
    }
    final bytes = await file.readAsBytes();
    final archive = ArchivePlus.unzip(bytes, options: options);
    return extractArchive(
      archive,
      destinationDirectory,
      securityPolicy: options.securityPolicy,
      overwrite: overwrite,
      onProgress: options.onProgress,
      cancelToken: options.cancelToken,
    );
  }

  /// Extracts a `.tar.gz` / `.tgz` file at [tarGzPath] into
  /// [destinationDirectory], returning the list of extracted relative paths.
  static Future<List<String>> extractTarGzFile(
    String tarGzPath,
    String destinationDirectory, {
    GZipOptions gzipOptions = const GZipOptions(),
    TarDecodeOptions tarOptions = const TarDecodeOptions(),
    bool overwrite = true,
  }) async {
    final file = File(tarGzPath);
    if (!await file.exists()) {
      throw ArchiveIoException('TAR.GZ file not found: "$tarGzPath".');
    }
    final bytes = await file.readAsBytes();
    final archive = ArchivePlus.untarGz(
      bytes,
      gzipOptions: gzipOptions,
      tarOptions: tarOptions,
    );
    return extractArchive(
      archive,
      destinationDirectory,
      securityPolicy: tarOptions.securityPolicy,
      overwrite: overwrite,
      onProgress: tarOptions.onProgress,
      cancelToken: tarOptions.cancelToken,
    );
  }

  /// Automatically detects and extracts [archivePath] into
  /// [destinationDirectory], returning the list of extracted relative paths.
  static Future<List<String>> extractAutoFile(
    String archivePath,
    String destinationDirectory, {
    String? password,
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
    ArchiveFilter? filter,
    bool overwrite = true,
    ArchiveProgressCallback? onProgress,
    ArchiveCancelToken? cancelToken,
  }) async {
    final file = File(archivePath);
    if (!await file.exists()) {
      throw ArchiveIoException('Archive file not found: "$archivePath".');
    }
    final bytes = await file.readAsBytes();
    final archive = ArchivePlus.decodeAuto(
      bytes,
      fileName: archivePath,
      password: password,
      securityPolicy: securityPolicy,
      filter: filter,
      onProgress: onProgress,
      cancelToken: cancelToken,
    );
    return extractArchive(
      archive,
      destinationDirectory,
      securityPolicy: securityPolicy,
      overwrite: overwrite,
      onProgress: onProgress,
      cancelToken: cancelToken,
    );
  }

  static Future<void> _verifyInsideRoot(
    String pathToCheck,
    String canonicalRoot,
    String entryName,
  ) async {
    final resolved = await Directory(pathToCheck).resolveSymbolicLinks();
    final rootWithSep = canonicalRoot.endsWith(Platform.pathSeparator)
        ? canonicalRoot
        : '$canonicalRoot${Platform.pathSeparator}';
    if (resolved != canonicalRoot && !resolved.startsWith(rootWithSep)) {
      throw ArchiveSecurityException(
        'Resolved extraction path escapes destination directory.',
        violation: ArchiveSecurityViolation.pathTraversal,
        entryName: entryName,
      );
    }
  }

  static String _normalizeNativePath(String p) => p.replaceAll('\\', '/');

  static String _relativePath(
    String entityPath,
    String resolvedRootPrefix,
    String rawRoot,
  ) {
    if (entityPath.startsWith(resolvedRootPrefix)) {
      return entityPath
          .substring(resolvedRootPrefix.length)
          .replaceAll('\\', '/');
    }
    final normEntity = _normalizeNativePath(entityPath);
    final normRoot = _normalizeNativePath(rawRoot);
    final prefix = normRoot.endsWith('/') ? normRoot : '$normRoot/';
    if (normEntity.startsWith(prefix)) {
      return normEntity.substring(prefix.length);
    }
    return normEntity;
  }
}

/// Offloads CPU-intensive archive and compression tasks onto a background
/// [Isolate] on native Dart and Flutter targets so UI frames stay smooth.
final class ArchiveIsolate {
  ArchiveIsolate._();

  /// Encodes [archive] into ZIP bytes on a background isolate.
  static Future<Uint8List> encodeZip(
    Archive archive, {
    CompressionLevel level = CompressionLevel.balanced,
    CompressionMethod method = CompressionMethod.deflate,
    bool autoStoreIfLarger = true,
    String? password,
    String? comment,
  }) {
    return Isolate.run(
      () => ArchivePlus.zip(
        archive,
        options: ZipEncodeOptions(
          level: level,
          method: method,
          autoStoreIfLarger: autoStoreIfLarger,
          password: password,
          comment: comment,
        ),
      ),
    );
  }

  /// Decodes ZIP [bytes] into an [Archive] on a background isolate.
  static Future<Archive> decodeZip(
    Uint8List bytes, {
    String? password,
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) {
    return Isolate.run(
      () => ArchivePlus.unzip(
        bytes,
        options: ZipDecodeOptions(
          password: password,
          securityPolicy: securityPolicy,
        ),
      ),
    );
  }

  /// Encodes [archive] into `.tar.gz` bytes on a background isolate.
  static Future<Uint8List> encodeTarGz(
    Archive archive, {
    CompressionLevel level = CompressionLevel.balanced,
  }) {
    return Isolate.run(
      () => ArchivePlus.tarGz(archive, gzipOptions: GZipOptions(level: level)),
    );
  }

  /// Decodes `.tar.gz` [bytes] into an [Archive] on a background isolate.
  static Future<Archive> decodeTarGz(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) {
    return Isolate.run(
      () => ArchivePlus.untarGz(
        bytes,
        gzipOptions: GZipOptions(securityPolicy: securityPolicy),
        tarOptions: TarDecodeOptions(securityPolicy: securityPolicy),
      ),
    );
  }

  /// Compresses [bytes] using GZIP on a background isolate.
  static Future<Uint8List> compressGzip(
    Uint8List bytes, {
    CompressionLevel level = CompressionLevel.balanced,
  }) {
    return Isolate.run(
      () => ArchivePlus.gzip(bytes, options: GZipOptions(level: level)),
    );
  }

  /// Decompresses GZIP [bytes] on a background isolate.
  static Future<Uint8List> decompressGzip(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) {
    return Isolate.run(
      () => ArchivePlus.gunzip(
        bytes,
        options: GZipOptions(securityPolicy: securityPolicy),
      ),
    );
  }

  /// Compresses [bytes] using BZip2 on a background isolate.
  static Future<Uint8List> compressBzip2(
    Uint8List bytes, {
    int blockSize100k = 9,
  }) {
    return Isolate.run(
      () => ArchivePlus.bzip2(
        bytes,
        options: BZip2Options(blockSize100k: blockSize100k),
      ),
    );
  }

  /// Decompresses BZip2 [bytes] on a background isolate.
  static Future<Uint8List> decompressBzip2(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) {
    return Isolate.run(
      () => ArchivePlus.bunzip2(
        bytes,
        options: BZip2Options(securityPolicy: securityPolicy),
      ),
    );
  }

  /// Compresses [bytes] using LZ4 Frame Format on a background isolate.
  static Future<Uint8List> compressLz4(
    Uint8List bytes, {
    Lz4BlockSize blockSize = Lz4BlockSize.mb4,
  }) {
    return Isolate.run(
      () => ArchivePlus.lz4(bytes, options: Lz4Options(blockSize: blockSize)),
    );
  }

  /// Decompresses LZ4 Frame Format [bytes] on a background isolate.
  static Future<Uint8List> decompressLz4(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) {
    return Isolate.run(
      () => ArchivePlus.unlz4(
        bytes,
        options: Lz4Options(securityPolicy: securityPolicy),
      ),
    );
  }
}

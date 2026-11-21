import 'dart:typed_data';

import '../archive_plus_facade.dart';
import '../core/archive.dart';
import '../core/archive_filter.dart';
import '../core/archive_options.dart';
import '../core/archive_progress.dart';
import '../core/archive_security.dart';

/// Platform-aware file-system archive operations.
///
/// On Web and WebAssembly targets where `dart:io` is unavailable, methods throw
/// [UnsupportedError]. On native Dart/Flutter targets, the native `dart:io`
/// implementation is automatically selected via conditional exports.
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
  }) {
    throw UnsupportedError(
      'ArchiveFileSystem.readDirectory requires dart:io (native platforms).',
    );
  }

  /// Extracts [archive] into [destinationDirectory] while enforcing
  /// [securityPolicy] against Zip-Slip and symlink escape attacks.
  static Future<List<String>> extractArchive(
    Archive archive,
    String destinationDirectory, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
    ArchiveFilter? filter,
    bool overwrite = true,
    ArchiveProgressCallback? onProgress,
    ArchiveCancelToken? cancelToken,
  }) {
    throw UnsupportedError(
      'ArchiveFileSystem.extractArchive requires dart:io (native platforms).',
    );
  }

  /// Compresses [sourceDirectory] directly to a ZIP file at [outputZipPath],
  /// returning the number of bytes written.
  static Future<int> compressDirectoryToZip(
    String sourceDirectory,
    String outputZipPath, {
    ZipEncodeOptions options = const ZipEncodeOptions(),
    ArchiveFilter? directoryFilter,
    bool followLinks = false,
  }) {
    throw UnsupportedError(
      'ArchiveFileSystem.compressDirectoryToZip requires dart:io.',
    );
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
  }) {
    throw UnsupportedError(
      'ArchiveFileSystem.compressDirectoryToTarGz requires dart:io.',
    );
  }

  /// Extracts a ZIP file at [zipPath] into [destinationDirectory], returning
  /// the list of extracted relative entry paths.
  static Future<List<String>> extractZipFile(
    String zipPath,
    String destinationDirectory, {
    ZipDecodeOptions options = const ZipDecodeOptions(),
    bool overwrite = true,
  }) {
    throw UnsupportedError(
      'ArchiveFileSystem.extractZipFile requires dart:io.',
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
  }) {
    throw UnsupportedError(
      'ArchiveFileSystem.extractTarGzFile requires dart:io.',
    );
  }

  /// Automatically detects and extracts [archivePath] (ZIP, TAR, TAR.GZ,
  /// TAR.BZ2, GZIP, BZip2, LZ4, or ZLIB) into [destinationDirectory].
  static Future<List<String>> extractAutoFile(
    String archivePath,
    String destinationDirectory, {
    String? password,
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
    ArchiveFilter? filter,
    bool overwrite = true,
    ArchiveProgressCallback? onProgress,
    ArchiveCancelToken? cancelToken,
  }) {
    throw UnsupportedError(
      'ArchiveFileSystem.extractAutoFile requires dart:io.',
    );
  }
}

/// Offloads CPU-intensive archive and compression tasks onto a background
/// isolate on native platforms so Flutter UI threads stay jank-free.
///
/// On Web and WebAssembly targets, operations execute asynchronously on the
/// event loop without requiring platform conditionals in caller code.
final class ArchiveIsolate {
  ArchiveIsolate._();

  /// Encodes [archive] into ZIP bytes asynchronously.
  static Future<Uint8List> encodeZip(
    Archive archive, {
    CompressionLevel level = CompressionLevel.balanced,
    CompressionMethod method = CompressionMethod.deflate,
    bool autoStoreIfLarger = true,
    String? password,
    String? comment,
  }) async {
    return ArchivePlus.zip(
      archive,
      options: ZipEncodeOptions(
        level: level,
        method: method,
        autoStoreIfLarger: autoStoreIfLarger,
        password: password,
        comment: comment,
      ),
    );
  }

  /// Decodes ZIP [bytes] into an [Archive] asynchronously.
  static Future<Archive> decodeZip(
    Uint8List bytes, {
    String? password,
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) async {
    return ArchivePlus.unzip(
      bytes,
      options: ZipDecodeOptions(
        password: password,
        securityPolicy: securityPolicy,
      ),
    );
  }

  /// Encodes [archive] into `.tar.gz` bytes asynchronously.
  static Future<Uint8List> encodeTarGz(
    Archive archive, {
    CompressionLevel level = CompressionLevel.balanced,
  }) async {
    return ArchivePlus.tarGz(archive, gzipOptions: GZipOptions(level: level));
  }

  /// Decodes `.tar.gz` [bytes] into an [Archive] asynchronously.
  static Future<Archive> decodeTarGz(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) async {
    return ArchivePlus.untarGz(
      bytes,
      gzipOptions: GZipOptions(securityPolicy: securityPolicy),
      tarOptions: TarDecodeOptions(securityPolicy: securityPolicy),
    );
  }

  /// Compresses [bytes] using GZIP asynchronously.
  static Future<Uint8List> compressGzip(
    Uint8List bytes, {
    CompressionLevel level = CompressionLevel.balanced,
  }) async {
    return ArchivePlus.gzip(bytes, options: GZipOptions(level: level));
  }

  /// Decompresses GZIP [bytes] asynchronously.
  static Future<Uint8List> decompressGzip(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) async {
    return ArchivePlus.gunzip(
      bytes,
      options: GZipOptions(securityPolicy: securityPolicy),
    );
  }

  /// Compresses [bytes] using BZip2 asynchronously.
  static Future<Uint8List> compressBzip2(
    Uint8List bytes, {
    int blockSize100k = 9,
  }) async {
    return ArchivePlus.bzip2(
      bytes,
      options: BZip2Options(blockSize100k: blockSize100k),
    );
  }

  /// Decompresses BZip2 [bytes] asynchronously.
  static Future<Uint8List> decompressBzip2(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) async {
    return ArchivePlus.bunzip2(
      bytes,
      options: BZip2Options(securityPolicy: securityPolicy),
    );
  }

  /// Compresses [bytes] using LZ4 Frame Format asynchronously.
  static Future<Uint8List> compressLz4(
    Uint8List bytes, {
    Lz4BlockSize blockSize = Lz4BlockSize.mb4,
  }) async {
    return ArchivePlus.lz4(bytes, options: Lz4Options(blockSize: blockSize));
  }

  /// Decompresses LZ4 Frame Format [bytes] asynchronously.
  static Future<Uint8List> decompressLz4(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) async {
    return ArchivePlus.unlz4(
      bytes,
      options: Lz4Options(securityPolicy: securityPolicy),
    );
  }
}

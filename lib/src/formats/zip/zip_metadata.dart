import '../../core/archive.dart';
import '../../core/archive_options.dart';

/// Zero-decompression metadata summary of a single entry parsed directly from
/// a ZIP archive's Central Directory.
final class ZipEntrySummary {
  /// Creates a [ZipEntrySummary].
  const ZipEntrySummary({
    required this.name,
    required this.type,
    required this.compressionMethodCode,
    required this.compressedSize,
    required this.uncompressedSize,
    required this.crc32,
    required this.modifiedTime,
    required this.permissions,
    required this.isEncrypted,
    required this.localHeaderOffset,
    this.comment,
  });

  /// Normalized POSIX entry name.
  final String name;

  /// Entry type (file, directory, or symbolic link).
  final ArchiveEntryType type;

  /// Raw PKWARE compression method identifier (`0` = store, `8` = deflate,
  /// `12` = bzip2).
  final int compressionMethodCode;

  /// Resolved [CompressionMethod], or `null` if unsupported.
  CompressionMethod? get compressionMethod =>
      CompressionMethod.fromZipCode(compressionMethodCode);

  /// Compressed payload size in bytes.
  final int compressedSize;

  /// Uncompressed payload size in bytes.
  final int uncompressedSize;

  /// Recorded IEEE CRC-32 checksum.
  final int crc32;

  /// Last modification timestamp in UTC.
  final DateTime modifiedTime;

  /// UNIX permission bits.
  final int permissions;

  /// Whether the entry is encrypted.
  final bool isEncrypted;

  /// Byte offset of this entry's Local File Header in the ZIP stream.
  final int localHeaderOffset;

  /// Optional per-entry comment.
  final String? comment;

  /// Whether this summary describes a regular file.
  bool get isFile => type == ArchiveEntryType.file;

  /// Whether this summary describes a directory.
  bool get isDirectory => type == ArchiveEntryType.directory;

  /// Compression ratio (`compressedSize / uncompressedSize`).
  double get compressionRatio =>
      uncompressedSize == 0 ? 1.0 : compressedSize / uncompressedSize;

  /// Space savings percentage (`0.0`..`100.0`).
  double get savedPercentage => uncompressedSize == 0
      ? 0.0
      : ((1.0 - compressionRatio) * 100.0).clamp(0.0, 100.0);

  @override
  String toString() =>
      'ZipEntrySummary($name, $uncompressedSize B -> $compressedSize B, '
      'method: $compressionMethodCode, encrypted: $isEncrypted)';
}

/// Zero-decompression Central Directory overview of a ZIP archive returned by
/// `ArchivePlus.inspectZip`.
final class ZipArchiveSummary {
  /// Creates a [ZipArchiveSummary].
  ZipArchiveSummary({
    required List<ZipEntrySummary> entries,
    required this.isZip64,
    this.comment,
  }) : entries = List<ZipEntrySummary>.unmodifiable(entries);

  /// All entries listed in the Central Directory.
  final List<ZipEntrySummary> entries;

  /// Whether the archive uses ZIP64 structures.
  final bool isZip64;

  /// Optional archive-level comment.
  final String? comment;

  /// Number of regular file entries.
  int get fileCount => entries.where((e) => e.isFile).length;

  /// Number of directory entries.
  int get directoryCount => entries.where((e) => e.isDirectory).length;

  /// Number of encrypted entries.
  int get encryptedCount => entries.where((e) => e.isEncrypted).length;

  /// Total uncompressed payload size across all entries.
  int get totalUncompressedBytes =>
      entries.fold(0, (sum, e) => sum + e.uncompressedSize);

  /// Total compressed payload size across all entries.
  int get totalCompressedBytes =>
      entries.fold(0, (sum, e) => sum + e.compressedSize);

  /// Overall space savings percentage (`0.0`..`100.0`).
  double get savedPercentage {
    final raw = totalUncompressedBytes;
    if (raw == 0) {
      return 0.0;
    }
    return ((1.0 - totalCompressedBytes / raw) * 100.0).clamp(0.0, 100.0);
  }

  /// Looks up a [ZipEntrySummary] by exact [name], or returns `null`.
  ZipEntrySummary? find(String name) {
    for (final entry in entries) {
      if (entry.name == name) {
        return entry;
      }
    }
    return null;
  }

  @override
  String toString() =>
      'ZipArchiveSummary(entries: ${entries.length}, raw: '
      '$totalUncompressedBytes B, compressed: $totalCompressedBytes B, '
      'zip64: $isZip64)';
}

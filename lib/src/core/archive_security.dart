import '../util/path_sanitizer.dart';
import 'archive_exceptions.dart';

/// Configurable security policy protecting applications from Zip-Slip path
/// traversal, Zip-Bomb memory exhaustion, symlink escapes, and corrupted data.
final class ArchiveSecurityPolicy {
  /// Creates a custom [ArchiveSecurityPolicy].
  const ArchiveSecurityPolicy({
    this.maxTotalUncompressedSize = 256 * 1024 * 1024,
    this.maxEntrySize = 100 * 1024 * 1024,
    this.maxEntryCount = 10000,
    this.maxCompressionRatio = 100.0,
    this.minRatioCheckBytes = 1024 * 1024,
    this.allowPathTraversal = false,
    this.allowSymlinks = false,
    this.strictChecksum = true,
  });

  /// Default balanced policy suitable for most mobile, desktop, web, and
  /// server apps (256 MiB total, 100 MiB per entry, 10,000 entries, 100× max
  /// ratio above 1 MiB, Zip-Slip & symlinks blocked, strict checksums on).
  static const ArchiveSecurityPolicy standard = ArchiveSecurityPolicy();

  /// Hardened policy recommended when accepting untrusted user uploads
  /// (50 MiB total, 10 MiB per entry, 1,000 entries, 50× max ratio above
  /// 256 KiB).
  static const ArchiveSecurityPolicy strict = ArchiveSecurityPolicy(
    maxTotalUncompressedSize: 50 * 1024 * 1024,
    maxEntrySize: 10 * 1024 * 1024,
    maxEntryCount: 1000,
    maxCompressionRatio: 50.0,
    minRatioCheckBytes: 256 * 1024,
    allowPathTraversal: false,
    allowSymlinks: false,
    strictChecksum: true,
  );

  /// Unrestricted policy for trusted internal pipelines handling massive
  /// archives. Checksum verification remains enabled by default.
  static const ArchiveSecurityPolicy unrestricted = ArchiveSecurityPolicy(
    maxTotalUncompressedSize: null,
    maxEntrySize: null,
    maxEntryCount: null,
    maxCompressionRatio: null,
    allowPathTraversal: false,
    allowSymlinks: true,
    strictChecksum: true,
  );

  /// Maximum total decompressed bytes across the entire archive (`null` means
  /// unlimited).
  final int? maxTotalUncompressedSize;

  /// Maximum decompressed bytes for any single entry or stream (`null` means
  /// unlimited).
  final int? maxEntrySize;

  /// Maximum number of entries allowed in an archive (`null` means unlimited).
  final int? maxEntryCount;

  /// Maximum allowed ratio of `uncompressedSize / compressedSize` once
  /// `uncompressedSize >= minRatioCheckBytes` (`null` disables ratio checks).
  final double? maxCompressionRatio;

  /// Minimum uncompressed size in bytes before [maxCompressionRatio] is
  /// enforced, preventing false positives on tiny repetitive payloads.
  final int minRatioCheckBytes;

  /// Whether entry paths may contain `..`, absolute roots, or drive letters.
  final bool allowPathTraversal;

  /// Whether symbolic links are permitted when extracting to disk.
  final bool allowSymlinks;

  /// Whether checksums (CRC-32, Adler-32, BZip2 CRC, XXH32) must match.
  final bool strictChecksum;

  /// Returns a copy of this policy with selectively overridden fields.
  ArchiveSecurityPolicy copyWith({
    int? maxTotalUncompressedSize,
    int? maxEntrySize,
    int? maxEntryCount,
    double? maxCompressionRatio,
    int? minRatioCheckBytes,
    bool? allowPathTraversal,
    bool? allowSymlinks,
    bool? strictChecksum,
  }) {
    return ArchiveSecurityPolicy(
      maxTotalUncompressedSize:
          maxTotalUncompressedSize ?? this.maxTotalUncompressedSize,
      maxEntrySize: maxEntrySize ?? this.maxEntrySize,
      maxEntryCount: maxEntryCount ?? this.maxEntryCount,
      maxCompressionRatio: maxCompressionRatio ?? this.maxCompressionRatio,
      minRatioCheckBytes: minRatioCheckBytes ?? this.minRatioCheckBytes,
      allowPathTraversal: allowPathTraversal ?? this.allowPathTraversal,
      allowSymlinks: allowSymlinks ?? this.allowSymlinks,
      strictChecksum: strictChecksum ?? this.strictChecksum,
    );
  }

  /// Validates and normalizes [rawPath] according to [allowPathTraversal].
  String sanitizePath(String rawPath, {bool isDirectory = false}) {
    return PathSanitizer.sanitize(
      rawPath,
      allowPathTraversal: allowPathTraversal,
      isDirectory: isDirectory,
    );
  }

  /// Ensures [count] does not exceed [maxEntryCount].
  void checkEntryCount(int count, {String? entryName}) {
    final limit = maxEntryCount;
    if (limit != null && count > limit) {
      throw ArchiveSecurityException(
        'Archive entry count ($count) exceeds policy limit ($limit).',
        violation: ArchiveSecurityViolation.entryCountLimitExceeded,
        entryName: entryName,
      );
    }
  }

  /// Ensures a single entry's uncompressed [size] does not exceed
  /// [maxEntrySize].
  void checkEntrySize(int size, {String? entryName}) {
    final limit = maxEntrySize;
    if (limit != null && size > limit) {
      throw ArchiveSecurityException(
        'Entry uncompressed size ($size bytes) exceeds policy limit '
        '($limit bytes).',
        violation: ArchiveSecurityViolation.entrySizeLimitExceeded,
        entryName: entryName,
      );
    }
  }

  /// Ensures cumulative [totalSize] does not exceed [maxTotalUncompressedSize].
  void checkTotalSize(int totalSize, {String? entryName}) {
    final limit = maxTotalUncompressedSize;
    if (limit != null && totalSize > limit) {
      throw ArchiveSecurityException(
        'Total uncompressed size ($totalSize bytes) exceeds policy limit '
        '($limit bytes).',
        violation: ArchiveSecurityViolation.totalSizeLimitExceeded,
        entryName: entryName,
      );
    }
  }

  /// Ensures the compression ratio does not violate [maxCompressionRatio].
  void checkCompressionRatio({
    required int compressedSize,
    required int uncompressedSize,
    String? entryName,
  }) {
    final maxRatio = maxCompressionRatio;
    if (maxRatio == null || uncompressedSize < minRatioCheckBytes) {
      return;
    }
    final effectiveCompressed = compressedSize <= 0 ? 1 : compressedSize;
    final ratio = uncompressedSize / effectiveCompressed;
    if (ratio > maxRatio) {
      throw ArchiveSecurityException(
        'Compression ratio (${ratio.toStringAsFixed(1)}x) exceeds policy '
        'limit (${maxRatio.toStringAsFixed(1)}x) — possible zip bomb.',
        violation: ArchiveSecurityViolation.compressionRatioExceeded,
        entryName: entryName,
      );
    }
  }

  /// Computes the tightest single-stream byte ceiling given [alreadyDecoded].
  int? effectiveSingleStreamLimit({int alreadyDecoded = 0}) {
    int? limit = maxEntrySize;
    final total = maxTotalUncompressedSize;
    if (total != null) {
      final remaining = total - alreadyDecoded;
      if (remaining < 0) {
        return 0;
      }
      if (limit == null || remaining < limit) {
        limit = remaining;
      }
    }
    return limit;
  }
}

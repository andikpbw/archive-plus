/// Typed exception hierarchy for all archive and compression operations.
library;

/// Base sealed exception for all errors produced by `archive_plus`.
///
/// Using a `sealed class` enables exhaustive Dart 3 `switch` handling over
/// every failure category:
///
/// ```dart
/// try {
///   ArchivePlus.unzip(bytes);
/// } on ArchiveException catch (error) {
///   switch (error) {
///     case ArchiveFormatException():
///       // Corrupted or unsupported data.
///     case ArchiveChecksumException():
///       // CRC32, Adler32, or XXH32 mismatch.
///     case ArchiveSecurityException():
///       // Zip-slip or zip-bomb policy violation.
///     case ArchivePasswordException():
///       // Missing or incorrect decryption password.
///     case ArchiveCancelledException():
///       // Cancelled via ArchiveCancelToken.
///     case ArchiveIoException():
///       // File system read/write error.
///   }
/// }
/// ```
sealed class ArchiveException implements Exception {
  /// Creates an [ArchiveException] with a descriptive [message] and optional
  /// [entryName] and [offset].
  const ArchiveException(this.message, {this.entryName, this.offset});

  /// Human-readable description of the error.
  final String message;

  /// Optional archive entry path associated with the error.
  final String? entryName;

  /// Optional byte offset in the input stream where the error occurred.
  final int? offset;

  @override
  String toString() {
    final buffer = StringBuffer('$runtimeType: $message');
    if (entryName != null) {
      buffer.write(' (entry: $entryName)');
    }
    if (offset != null) {
      buffer.write(' (offset: $offset)');
    }
    return buffer.toString();
  }
}

/// Thrown when input data is malformed, truncated, or uses an unsupported
/// format or compression method.
final class ArchiveFormatException extends ArchiveException {
  /// Creates an [ArchiveFormatException].
  const ArchiveFormatException(super.message, {super.entryName, super.offset});
}

/// Thrown when a data integrity checksum (CRC-32, Adler-32, BZip2 CRC, or
/// XXH32) fails verification.
final class ArchiveChecksumException extends ArchiveException {
  /// Creates an [ArchiveChecksumException] with the [expected] and [actual]
  /// checksum values.
  const ArchiveChecksumException(
    super.message, {
    required this.expected,
    required this.actual,
    super.entryName,
    super.offset,
  });

  /// The checksum recorded in the archive or stream header/trailer.
  final int expected;

  /// The checksum computed from the decoded payload.
  final int actual;

  @override
  String toString() {
    final expHex = expected.toRadixString(16).padLeft(8, '0');
    final actHex = actual.toRadixString(16).padLeft(8, '0');
    return '${super.toString()} [expected: 0x$expHex, actual: 0x$actHex]';
  }
}

/// Reason a security guard rejected an archive operation.
enum ArchiveSecurityViolation {
  /// Entry path attempts directory traversal (`..`, absolute path, or drive).
  pathTraversal,

  /// Single entry exceeds `maxEntrySize`.
  entrySizeLimitExceeded,

  /// Total decompressed size exceeds `maxTotalUncompressedSize`.
  totalSizeLimitExceeded,

  /// Total entry count exceeds `maxEntryCount`.
  entryCountLimitExceeded,

  /// Compression ratio exceeds `maxCompressionRatio` (potential zip bomb).
  compressionRatioExceeded,

  /// Symlink extraction was disallowed by policy or escapes destination root.
  disallowedSymlink,
}

/// Thrown when an archive violates an active security policy (for example,
/// Zip-Slip path traversal or Zip-Bomb decompression limits).
final class ArchiveSecurityException extends ArchiveException {
  /// Creates an [ArchiveSecurityException].
  const ArchiveSecurityException(
    super.message, {
    required this.violation,
    super.entryName,
    super.offset,
  });

  /// The specific security rule that was violated.
  final ArchiveSecurityViolation violation;
}

/// Thrown when an encrypted archive entry is missing a password or the
/// supplied password is incorrect.
final class ArchivePasswordException extends ArchiveException {
  /// Creates an [ArchivePasswordException].
  const ArchivePasswordException(
    super.message, {
    super.entryName,
    super.offset,
  });
}

/// Thrown when an operation is cancelled via an active cancellation token.
final class ArchiveCancelledException extends ArchiveException {
  /// Creates an [ArchiveCancelledException].
  const ArchiveCancelledException([
    super.message = 'Archive operation was cancelled.',
  ]);
}

/// Thrown when a native file system operation fails during archive I/O.
final class ArchiveIoException extends ArchiveException {
  /// Creates an [ArchiveIoException].
  const ArchiveIoException(super.message, {super.entryName, this.cause});

  /// Underlying platform exception, if available.
  final Object? cause;
}

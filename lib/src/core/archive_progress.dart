import 'archive_exceptions.dart';

/// Lifecycle phase reported by [ArchiveProgress].
enum ArchivePhase {
  /// Scanning headers or central directory metadata without decompressing.
  inspecting,

  /// Reading source data or file entries.
  reading,

  /// Compressing payload data.
  compressing,

  /// Decompressing payload data.
  decompressing,

  /// Writing archive headers, entries, or extracted files.
  writing,

  /// Verifying data integrity checksums.
  verifying,

  /// Operation finished cleanly.
  completed,
}

/// Real-time progress snapshot emitted during archive encoding, decoding, or
/// file-system extraction.
final class ArchiveProgress {
  /// Creates an [ArchiveProgress] snapshot.
  const ArchiveProgress({
    required this.phase,
    required this.processedEntries,
    required this.totalEntries,
    this.entryName,
    this.bytesProcessed = 0,
    this.totalBytes = 0,
    this.compressedBytes = 0,
  });

  /// Current processing phase.
  final ArchivePhase phase;

  /// Name of the entry currently being processed, if applicable.
  final String? entryName;

  /// Number of entries processed so far.
  final int processedEntries;

  /// Total number of entries expected (may be `0` if unknown).
  final int totalEntries;

  /// Cumulative uncompressed bytes processed so far.
  final int bytesProcessed;

  /// Total expected uncompressed bytes (may be `0` if unknown).
  final int totalBytes;

  /// Cumulative compressed bytes produced or read so far.
  final int compressedBytes;

  /// Normalized completion fraction in the range `[0.0, 1.0]`.
  double get fraction {
    if (phase == ArchivePhase.completed) {
      return 1.0;
    }
    if (totalBytes > 0) {
      return (bytesProcessed / totalBytes).clamp(0.0, 1.0);
    }
    if (totalEntries > 0) {
      return (processedEntries / totalEntries).clamp(0.0, 1.0);
    }
    return 0.0;
  }

  /// Compression ratio (`compressedBytes / bytesProcessed`), or `1.0` when
  /// uncompressed byte count is `0`.
  double get compressionRatio {
    if (bytesProcessed <= 0) {
      return 1.0;
    }
    return compressedBytes / bytesProcessed;
  }

  @override
  String toString() {
    final pct = (fraction * 100).toStringAsFixed(1);
    return 'ArchiveProgress(phase: ${phase.name}, $processedEntries/'
        '$totalEntries, $pct%, entry: $entryName)';
  }
}

/// Callback invoked periodically as archive work progresses.
typedef ArchiveProgressCallback = void Function(ArchiveProgress progress);

/// Cooperative cancellation token passed to archive encoders, decoders, and
/// disk extraction routines.
final class ArchiveCancelToken {
  /// Creates an active, uncancelled [ArchiveCancelToken].
  ArchiveCancelToken();

  bool _isCancelled = false;
  String? _reason;

  /// Whether [cancel] has been called.
  bool get isCancelled => _isCancelled;

  /// Optional human-readable cancellation reason.
  String? get reason => _reason;

  /// Requests cancellation of any operation observing this token.
  void cancel([String? reason]) {
    _isCancelled = true;
    _reason = reason;
  }

  /// Throws [ArchiveCancelledException] if [isCancelled] is `true`.
  void throwIfCancelled() {
    if (_isCancelled) {
      throw ArchiveCancelledException(
        _reason ?? 'Archive operation was cancelled.',
      );
    }
  }
}

import '../util/path_sanitizer.dart';

/// Declarative filter for selectively including or excluding archive entries
/// during packing, unpacking, inspection, or directory traversal.
final class ArchiveFilter {
  /// Creates an [ArchiveFilter].
  const ArchiveFilter({
    this.includeGlobs = const <String>[],
    this.excludeGlobs = const <String>[],
    this.extensions = const <String>[],
    this.maxUncompressedSize,
    this.minUncompressedSize,
    this.includeDirectories = true,
    this.predicate,
  });

  /// Glob patterns that an entry path must match to be included (empty means
  /// all paths match).
  final List<String> includeGlobs;

  /// Glob patterns that exclude matching entry paths (takes precedence over
  /// [includeGlobs]).
  final List<String> excludeGlobs;

  /// Allowed file extensions (case-insensitive, with or without leading `.`).
  final List<String> extensions;

  /// Optional maximum uncompressed entry size in bytes.
  final int? maxUncompressedSize;

  /// Optional minimum uncompressed entry size in bytes.
  final int? minUncompressedSize;

  /// Whether directory entries are included.
  final bool includeDirectories;

  /// Optional custom filter predicate receiving `(path, size, isDirectory)`.
  final bool Function(String path, int? size, bool isDirectory)? predicate;

  /// Evaluates whether an entry with [path], optional [size], and [isDirectory]
  /// passes this filter.
  bool matches(String path, {int? size, bool isDirectory = false}) {
    if (isDirectory && !includeDirectories) {
      return false;
    }

    final normalized = path.replaceAll('\\', '/');

    for (final pattern in excludeGlobs) {
      if (PathSanitizer.matchesGlob(normalized, pattern)) {
        return false;
      }
    }

    if (includeGlobs.isNotEmpty) {
      var matched = false;
      for (final pattern in includeGlobs) {
        if (PathSanitizer.matchesGlob(normalized, pattern)) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        return false;
      }
    }

    if (!isDirectory && extensions.isNotEmpty) {
      final lower = normalized.toLowerCase();
      var extMatched = false;
      for (final ext in extensions) {
        final dotted = ext.startsWith('.')
            ? ext.toLowerCase()
            : '.${ext.toLowerCase()}';
        if (lower.endsWith(dotted)) {
          extMatched = true;
          break;
        }
      }
      if (!extMatched) {
        return false;
      }
    }

    if (!isDirectory && size != null) {
      if (maxUncompressedSize != null && size > maxUncompressedSize!) {
        return false;
      }
      if (minUncompressedSize != null && size < minUncompressedSize!) {
        return false;
      }
    }

    final custom = predicate;
    if (custom != null && !custom(normalized, size, isDirectory)) {
      return false;
    }

    return true;
  }
}

import '../core/archive_exceptions.dart';

/// Zero-dependency POSIX archive path sanitization and glob matching utilities.
final class PathSanitizer {
  PathSanitizer._();

  /// Normalizes an archive entry path to forward-slash POSIX format and
  /// validates it against Zip-Slip path traversal attacks.
  ///
  /// Throws [ArchiveSecurityException] with
  /// [ArchiveSecurityViolation.pathTraversal] when [allowPathTraversal] is
  /// `false` and [rawPath] contains null bytes, absolute roots, Windows drive
  /// prefixes, or `..` parent traversal segments.
  static String sanitize(
    String rawPath, {
    bool allowPathTraversal = false,
    bool isDirectory = false,
  }) {
    if (rawPath.contains('\u0000')) {
      throw ArchiveSecurityException(
        'Archive entry path contains a NUL byte.',
        violation: ArchiveSecurityViolation.pathTraversal,
        entryName: rawPath,
      );
    }

    var normalized = rawPath.replaceAll('\\', '/');

    if (!allowPathTraversal) {
      if (normalized.startsWith('/')) {
        throw ArchiveSecurityException(
          'Absolute path is not allowed in archive entry: "$rawPath".',
          violation: ArchiveSecurityViolation.pathTraversal,
          entryName: rawPath,
        );
      }
      if (normalized.length >= 2 &&
          normalized.codeUnitAt(1) == 0x3a && // ':'
          _isAsciiLetter(normalized.codeUnitAt(0))) {
        throw ArchiveSecurityException(
          'Windows drive prefix is not allowed in archive entry: "$rawPath".',
          violation: ArchiveSecurityViolation.pathTraversal,
          entryName: rawPath,
        );
      }
    }

    final parts = normalized.split('/');
    final cleanParts = <String>[];

    for (final part in parts) {
      if (part.isEmpty || part == '.') {
        continue;
      }
      if (part == '..') {
        if (!allowPathTraversal) {
          throw ArchiveSecurityException(
            'Parent directory traversal ("..") detected in archive entry: '
            '"$rawPath".',
            violation: ArchiveSecurityViolation.pathTraversal,
            entryName: rawPath,
          );
        }
        if (cleanParts.isNotEmpty && cleanParts.last != '..') {
          cleanParts.removeLast();
        } else {
          cleanParts.add('..');
        }
        continue;
      }
      cleanParts.add(part);
    }

    normalized = cleanParts.join('/');
    if (isDirectory && normalized.isNotEmpty && !normalized.endsWith('/')) {
      normalized = '$normalized/';
    }
    return normalized;
  }

  /// Checks whether [path] matches a POSIX glob [pattern].
  ///
  /// Supports `*` (any characters except `/`), `**` (any characters including
  /// `/`), `?` (single non-`/` character), and character classes `[abc]`.
  static bool matchesGlob(String path, String pattern) {
    final normPath = path.replaceAll('\\', '/');
    final normPattern = pattern.replaceAll('\\', '/');
    final regex = _globToRegExp(normPattern);
    return regex.hasMatch(normPath);
  }

  static RegExp _globToRegExp(String pattern) {
    final buffer = StringBuffer('^');
    var i = 0;
    while (i < pattern.length) {
      final ch = pattern[i];
      if (ch == '*') {
        if (i + 1 < pattern.length && pattern[i + 1] == '*') {
          // Consume `**/` cleanly so `**/*.dart` also matches `main.dart`.
          if (i + 2 < pattern.length && pattern[i + 2] == '/') {
            buffer.write('(?:.*/)?');
            i += 3;
          } else {
            buffer.write('.*');
            i += 2;
          }
        } else {
          buffer.write('[^/]*');
          i++;
        }
      } else if (ch == '?') {
        buffer.write('[^/]');
        i++;
      } else if (ch == '[') {
        final close = pattern.indexOf(']', i + 1);
        if (close != -1) {
          var cls = pattern.substring(i + 1, close);
          if (cls.startsWith('!')) {
            cls = '^${cls.substring(1)}';
          }
          buffer.write('[$cls]');
          i = close + 1;
        } else {
          buffer.write(r'\[');
          i++;
        }
      } else {
        buffer.write(RegExp.escape(ch));
        i++;
      }
    }
    buffer.write(r'$');
    return RegExp(buffer.toString());
  }

  static bool _isAsciiLetter(int code) {
    return (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
  }
}

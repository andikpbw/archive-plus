import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import '../util/byte_buffer.dart';
import '../util/checksums.dart';
import 'archive_filter.dart';
import 'archive_options.dart';

/// Type of entry stored inside an [Archive].
enum ArchiveEntryType {
  /// Regular binary or text file.
  file,

  /// Directory container entry.
  directory,

  /// Symbolic link referencing [ArchiveEntry.linkTarget].
  symbolicLink,

  /// Hard link referencing [ArchiveEntry.linkTarget].
  hardLink,
}

/// Immutable-friendly representation of a single file, directory, or link
/// inside an [Archive].
final class ArchiveEntry {
  /// Creates an [ArchiveEntry] backed by raw [bytes].
  ArchiveEntry({
    required this.name,
    List<int>? bytes,
    this.type = ArchiveEntryType.file,
    int? compressedSize,
    int? crc32,
    DateTime? modifiedTime,
    int? permissions,
    this.comment,
    this.linkTarget,
    this.compressionMethod,
    this.isEncrypted = false,
    Map<String, String>? metadata,
  }) : _bytes = bytes == null ? Uint8List(0) : asUint8List(bytes),
       compressedSize = compressedSize ?? (bytes?.length ?? 0),
       _crc32 = crc32,
       modifiedTime = (modifiedTime ?? DateTime.now().toUtc()).toUtc(),
       permissions =
           permissions ?? (type == ArchiveEntryType.directory ? 0x1ed : 0x1a4),
       metadata = metadata == null
           ? const <String, String>{}
           : Map<String, String>.unmodifiable(metadata);

  /// Creates a regular file [ArchiveEntry] from raw [bytes].
  factory ArchiveEntry.file(
    String name,
    List<int> bytes, {
    DateTime? modifiedTime,
    int permissions = 0x1a4,
    String? comment,
    CompressionMethod? compressionMethod,
    Map<String, String>? metadata,
  }) {
    return ArchiveEntry(
      name: name,
      bytes: bytes,
      type: ArchiveEntryType.file,
      modifiedTime: modifiedTime,
      permissions: permissions,
      comment: comment,
      compressionMethod: compressionMethod,
      metadata: metadata,
    );
  }

  /// Creates a UTF-8 text file [ArchiveEntry].
  factory ArchiveEntry.text(
    String name,
    String content, {
    DateTime? modifiedTime,
    int permissions = 0x1a4,
    String? comment,
    CompressionMethod? compressionMethod,
    Map<String, String>? metadata,
  }) {
    return ArchiveEntry.file(
      name,
      utf8.encode(content),
      modifiedTime: modifiedTime,
      permissions: permissions,
      comment: comment,
      compressionMethod: compressionMethod,
      metadata: metadata,
    );
  }

  /// Creates a directory [ArchiveEntry].
  factory ArchiveEntry.directory(
    String name, {
    DateTime? modifiedTime,
    int permissions = 0x1ed,
    String? comment,
    Map<String, String>? metadata,
  }) {
    final normalized = name.endsWith('/') ? name : '$name/';
    return ArchiveEntry(
      name: normalized,
      type: ArchiveEntryType.directory,
      modifiedTime: modifiedTime,
      permissions: permissions,
      comment: comment,
      compressionMethod: CompressionMethod.store,
      metadata: metadata,
    );
  }

  /// Creates a symbolic link [ArchiveEntry].
  factory ArchiveEntry.symbolicLink(
    String name,
    String target, {
    DateTime? modifiedTime,
    int permissions = 0x1ff,
    Map<String, String>? metadata,
  }) {
    return ArchiveEntry(
      name: name,
      type: ArchiveEntryType.symbolicLink,
      linkTarget: target,
      modifiedTime: modifiedTime,
      permissions: permissions,
      compressionMethod: CompressionMethod.store,
      metadata: metadata,
    );
  }

  /// Normalized POSIX entry path inside the archive.
  final String name;

  /// Entry kind (file, directory, symlink, or hard link).
  final ArchiveEntryType type;

  final Uint8List _bytes;
  int? _crc32;

  /// Encoded compressed size in bytes (when decoded from a compressed archive).
  final int compressedSize;

  /// Last modification timestamp in UTC.
  final DateTime modifiedTime;

  /// UNIX file mode / permission bits (e.g., `0644` = `0x1a4`, `0755` = `0x1ed`).
  final int permissions;

  /// Optional per-entry comment (primarily used by ZIP archives).
  final String? comment;

  /// Link target path when [type] is [ArchiveEntryType.symbolicLink] or
  /// [ArchiveEntryType.hardLink].
  final String? linkTarget;

  /// Optional preferred or observed compression method for this entry.
  final CompressionMethod? compressionMethod;

  /// Whether this entry was encrypted in the source archive.
  final bool isEncrypted;

  /// Unmodifiable custom metadata attributes (such as TAR PAX headers).
  final Map<String, String> metadata;

  /// Raw uncompressed payload bytes.
  Uint8List get bytes => _bytes;

  /// Uncompressed size in bytes.
  int get size => _bytes.length;

  /// Whether this entry represents a regular file.
  bool get isFile => type == ArchiveEntryType.file;

  /// Whether this entry represents a directory.
  bool get isDirectory => type == ArchiveEntryType.directory;

  /// Whether this entry represents a symbolic link.
  bool get isSymbolicLink => type == ArchiveEntryType.symbolicLink;

  /// Computes (and caches) the IEEE CRC-32 checksum of [bytes].
  int get crc32 => _crc32 ??= Crc32.compute(_bytes);

  /// Decodes [bytes] as a UTF-8 string.
  String readAsString({bool allowMalformed = false}) {
    return utf8.decode(_bytes, allowMalformed: allowMalformed);
  }

  /// Decodes [bytes] as JSON.
  Object? readAsJson() => jsonDecode(readAsString());

  /// Ratio of `compressedSize / size`, or `1.0` for empty entries.
  double get compressionRatio => size == 0 ? 1.0 : compressedSize / size;

  /// Creates a modified copy of this [ArchiveEntry].
  ArchiveEntry copyWith({
    String? name,
    List<int>? bytes,
    ArchiveEntryType? type,
    int? compressedSize,
    int? crc32,
    DateTime? modifiedTime,
    int? permissions,
    String? comment,
    String? linkTarget,
    CompressionMethod? compressionMethod,
    bool? isEncrypted,
    Map<String, String>? metadata,
  }) {
    return ArchiveEntry(
      name: name ?? this.name,
      bytes: bytes ?? _bytes,
      type: type ?? this.type,
      compressedSize: compressedSize ?? this.compressedSize,
      crc32: crc32 ?? (bytes == null ? _crc32 : null),
      modifiedTime: modifiedTime ?? this.modifiedTime,
      permissions: permissions ?? this.permissions,
      comment: comment ?? this.comment,
      linkTarget: linkTarget ?? this.linkTarget,
      compressionMethod: compressionMethod ?? this.compressionMethod,
      isEncrypted: isEncrypted ?? this.isEncrypted,
      metadata: metadata ?? this.metadata,
    );
  }

  @override
  String toString() => 'ArchiveEntry($name, ${type.name}, $size B)';
}

/// Summary statistics computed across all entries of an [Archive].
final class ArchiveStats {
  /// Creates an [ArchiveStats] summary.
  const ArchiveStats({
    required this.entryCount,
    required this.fileCount,
    required this.directoryCount,
    required this.linkCount,
    required this.totalUncompressedBytes,
    required this.totalCompressedBytes,
  });

  /// Total number of entries.
  final int entryCount;

  /// Number of regular files.
  final int fileCount;

  /// Number of directory entries.
  final int directoryCount;

  /// Number of symbolic and hard link entries.
  final int linkCount;

  /// Sum of uncompressed bytes across all entries.
  final int totalUncompressedBytes;

  /// Sum of compressed bytes across all entries.
  final int totalCompressedBytes;

  /// Bytes saved by compression (clamped at `0`).
  int get savedBytes {
    final diff = totalUncompressedBytes - totalCompressedBytes;
    return diff > 0 ? diff : 0;
  }

  /// Overall ratio `totalCompressedBytes / totalUncompressedBytes`.
  double get compressionRatio {
    if (totalUncompressedBytes == 0) {
      return 1.0;
    }
    return totalCompressedBytes / totalUncompressedBytes;
  }

  /// Space savings percentage (`0.0`..`100.0`).
  double get savedPercentage {
    if (totalUncompressedBytes == 0) {
      return 0.0;
    }
    return ((1.0 - compressionRatio) * 100.0).clamp(0.0, 100.0);
  }

  @override
  String toString() {
    return 'ArchiveStats(files: $fileCount, dirs: $directoryCount, '
        'raw: $totalUncompressedBytes B, compressed: $totalCompressedBytes B, '
        'saved: ${savedPercentage.toStringAsFixed(1)}%)';
  }
}

/// Result of comparing two [Archive] instances via [Archive.diff].
final class ArchiveDiff {
  /// Creates an [ArchiveDiff].
  const ArchiveDiff({
    required this.added,
    required this.removed,
    required this.modified,
    required this.unchanged,
  });

  /// Entries present in the target archive but missing from the baseline.
  final List<ArchiveEntry> added;

  /// Entries present in the baseline archive but missing from the target.
  final List<ArchiveEntry> removed;

  /// Entries present in both archives whose size, type, or content changed.
  final List<ArchiveEntry> modified;

  /// Entries identical in both archives.
  final List<ArchiveEntry> unchanged;

  /// Whether any entries were added, removed, or modified.
  bool get hasChanges =>
      added.isNotEmpty || removed.isNotEmpty || modified.isNotEmpty;

  @override
  String toString() {
    return 'ArchiveDiff(added: ${added.length}, removed: ${removed.length}, '
        'modified: ${modified.length}, unchanged: ${unchanged.length})';
  }
}

/// In-memory container holding a collection of [ArchiveEntry] objects.
final class Archive extends IterableBase<ArchiveEntry> {
  /// Creates an [Archive], optionally pre-populated with [entries] and a
  /// top-level [comment].
  Archive({Iterable<ArchiveEntry>? entries, this.comment}) {
    if (entries != null) {
      for (final entry in entries) {
        add(entry);
      }
    }
  }

  final List<ArchiveEntry> _entries = <ArchiveEntry>[];
  final Map<String, int> _index = <String, int>{};

  /// Optional archive-level comment.
  String? comment;

  /// Unmodifiable view of all entries in insertion order.
  List<ArchiveEntry> get entries => List<ArchiveEntry>.unmodifiable(_entries);

  @override
  Iterator<ArchiveEntry> get iterator => _entries.iterator;

  @override
  int get length => _entries.length;

  /// Adds or replaces an [entry] in the archive.
  ///
  /// If an entry with the same [ArchiveEntry.name] already exists, it is
  /// replaced in place.
  void add(ArchiveEntry entry) {
    final existingIndex = _index[entry.name];
    if (existingIndex != null) {
      _entries[existingIndex] = entry;
    } else {
      _index[entry.name] = _entries.length;
      _entries.add(entry);
    }
  }

  /// Adds all [entries] to this archive.
  void addAll(Iterable<ArchiveEntry> entries) {
    for (final entry in entries) {
      add(entry);
    }
  }

  /// Finds an entry by exact [name], or returns `null` if absent.
  ArchiveEntry? find(String name) {
    final idx = _index[name];
    return idx == null ? null : _entries[idx];
  }

  /// Returns `true` if an entry with [name] exists in this archive.
  bool containsEntry(String name) => _index.containsKey(name);

  /// Removes the entry named [name], returning the removed entry or `null`.
  ArchiveEntry? remove(String name) {
    final idx = _index.remove(name);
    if (idx == null) {
      return null;
    }
    final removed = _entries.removeAt(idx);
    // Re-index trailing entries.
    for (var i = idx; i < _entries.length; i++) {
      _index[_entries[i].name] = i;
    }
    return removed;
  }

  /// Removes all entries from this archive.
  void clear() {
    _entries.clear();
    _index.clear();
  }

  /// Returns a new [Archive] containing only entries matching [filter].
  Archive whereFiltered(ArchiveFilter filter) {
    final filtered = Archive(comment: comment);
    for (final entry in _entries) {
      if (filter.matches(
        entry.name,
        size: entry.size,
        isDirectory: entry.isDirectory,
      )) {
        filtered.add(entry);
      }
    }
    return filtered;
  }

  /// Returns all regular file paths in the archive.
  List<String> get filePaths =>
      _entries.where((e) => e.isFile).map((e) => e.name).toList();

  /// Returns all directory paths in the archive.
  List<String> get directoryPaths =>
      _entries.where((e) => e.isDirectory).map((e) => e.name).toList();

  /// Computes aggregate size and compression statistics for this archive.
  ArchiveStats get stats {
    var files = 0;
    var dirs = 0;
    var links = 0;
    var rawBytes = 0;
    var compBytes = 0;
    for (final entry in _entries) {
      switch (entry.type) {
        case ArchiveEntryType.file:
          files++;
          rawBytes += entry.size;
          compBytes += entry.compressedSize;
        case ArchiveEntryType.directory:
          dirs++;
        case ArchiveEntryType.symbolicLink:
        case ArchiveEntryType.hardLink:
          links++;
      }
    }
    return ArchiveStats(
      entryCount: _entries.length,
      fileCount: files,
      directoryCount: dirs,
      linkCount: links,
      totalUncompressedBytes: rawBytes,
      totalCompressedBytes: compBytes,
    );
  }

  /// Compares this archive (baseline) against [other] (target), reporting
  /// added, removed, modified, and unchanged entries.
  ArchiveDiff diff(Archive other) {
    final added = <ArchiveEntry>[];
    final removed = <ArchiveEntry>[];
    final modified = <ArchiveEntry>[];
    final unchanged = <ArchiveEntry>[];

    for (final targetEntry in other._entries) {
      final baseEntry = find(targetEntry.name);
      if (baseEntry == null) {
        added.add(targetEntry);
      } else if (_entriesEqual(baseEntry, targetEntry)) {
        unchanged.add(targetEntry);
      } else {
        modified.add(targetEntry);
      }
    }

    for (final baseEntry in _entries) {
      if (!other.containsEntry(baseEntry.name)) {
        removed.add(baseEntry);
      }
    }

    return ArchiveDiff(
      added: added,
      removed: removed,
      modified: modified,
      unchanged: unchanged,
    );
  }

  static bool _entriesEqual(ArchiveEntry a, ArchiveEntry b) {
    if (a.type != b.type || a.size != b.size || a.linkTarget != b.linkTarget) {
      return false;
    }
    if (a.crc32 != b.crc32) {
      return false;
    }
    final ab = a.bytes;
    final bb = b.bytes;
    for (var i = 0; i < ab.length; i++) {
      if (ab[i] != bb[i]) {
        return false;
      }
    }
    return true;
  }
}

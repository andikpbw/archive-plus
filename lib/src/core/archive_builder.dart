import 'dart:convert';
import 'dart:typed_data';

import '../codecs/bzip2_codec.dart';
import '../codecs/gzip_codec.dart';
import '../formats/tar/tar_encoder.dart';
import '../formats/zip/zip_encoder.dart';
import 'archive.dart';
import 'archive_options.dart';

/// Fluent builder for assembling and encoding [Archive] containers with minimal
/// boilerplate.
///
/// ```dart
/// final zipBytes = ArchiveBuilder()
///     .addText('README.md', '# ArchivePlus')
///     .addJson('meta/info.json', {'version': '1.0.0'})
///     .addDirectory('empty/')
///     .withComment('Created with ArchivePlus')
///     .encodeZip();
/// ```
final class ArchiveBuilder {
  /// Creates an empty [ArchiveBuilder].
  ArchiveBuilder();

  final Archive _archive = Archive();

  /// Adds a binary file entry at [path].
  ArchiveBuilder addBytes(
    String path,
    List<int> bytes, {
    DateTime? modifiedTime,
    int permissions = 0x1a4,
    String? comment,
    CompressionMethod? compression,
    Map<String, String>? metadata,
  }) {
    _archive.add(
      ArchiveEntry.file(
        path,
        bytes,
        modifiedTime: modifiedTime,
        permissions: permissions,
        comment: comment,
        compressionMethod: compression,
        metadata: metadata,
      ),
    );
    return this;
  }

  /// Adds a UTF-8 text file entry at [path].
  ArchiveBuilder addText(
    String path,
    String content, {
    DateTime? modifiedTime,
    int permissions = 0x1a4,
    String? comment,
    CompressionMethod? compression,
    Map<String, String>? metadata,
  }) {
    _archive.add(
      ArchiveEntry.text(
        path,
        content,
        modifiedTime: modifiedTime,
        permissions: permissions,
        comment: comment,
        compressionMethod: compression,
        metadata: metadata,
      ),
    );
    return this;
  }

  /// Encodes [value] as JSON (optionally pretty-printed) and adds it at [path].
  ArchiveBuilder addJson(
    String path,
    Object? value, {
    bool pretty = false,
    DateTime? modifiedTime,
    int permissions = 0x1a4,
    String? comment,
    CompressionMethod? compression,
  }) {
    final encoded = pretty
        ? const JsonEncoder.withIndent('  ').convert(value)
        : jsonEncode(value);
    return addText(
      path,
      encoded,
      modifiedTime: modifiedTime,
      permissions: permissions,
      comment: comment,
      compression: compression,
    );
  }

  /// Adds an explicit directory entry at [path].
  ArchiveBuilder addDirectory(
    String path, {
    DateTime? modifiedTime,
    int permissions = 0x1ed,
    String? comment,
  }) {
    _archive.add(
      ArchiveEntry.directory(
        path,
        modifiedTime: modifiedTime,
        permissions: permissions,
        comment: comment,
      ),
    );
    return this;
  }

  /// Adds a symbolic link entry at [path] pointing to [target].
  ArchiveBuilder addSymlink(
    String path,
    String target, {
    DateTime? modifiedTime,
    int permissions = 0x1ff,
  }) {
    _archive.add(
      ArchiveEntry.symbolicLink(
        path,
        target,
        modifiedTime: modifiedTime,
        permissions: permissions,
      ),
    );
    return this;
  }

  /// Adds a pre-constructed [ArchiveEntry].
  ArchiveBuilder addEntry(ArchiveEntry entry) {
    _archive.add(entry);
    return this;
  }

  /// Adds multiple [ArchiveEntry] objects.
  ArchiveBuilder addEntries(Iterable<ArchiveEntry> entries) {
    _archive.addAll(entries);
    return this;
  }

  /// Sets the top-level archive [comment].
  ArchiveBuilder withComment(String comment) {
    _archive.comment = comment;
    return this;
  }

  /// Builds and returns the assembled [Archive].
  Archive build() {
    return Archive(entries: _archive.entries, comment: _archive.comment);
  }

  /// Builds and encodes the archive directly into ZIP bytes.
  Uint8List encodeZip({ZipEncodeOptions options = const ZipEncodeOptions()}) {
    return ZipEncoder.encode(build(), options: options);
  }

  /// Builds and encodes the archive directly into POSIX TAR bytes.
  Uint8List encodeTar({TarEncodeOptions options = const TarEncodeOptions()}) {
    return TarEncoder.encode(build(), options: options);
  }

  /// Builds and encodes the archive directly into `.tar.gz` bytes.
  Uint8List encodeTarGz({
    TarEncodeOptions tarOptions = const TarEncodeOptions(),
    GZipOptions gzipOptions = const GZipOptions(),
  }) {
    final tarBytes = encodeTar(options: tarOptions);
    return GZipPlusCodec.encodeBytes(tarBytes, options: gzipOptions);
  }

  /// Builds and encodes the archive directly into `.tar.bz2` bytes.
  Uint8List encodeTarBz2({
    TarEncodeOptions tarOptions = const TarEncodeOptions(),
    BZip2Options bzip2Options = const BZip2Options(),
  }) {
    final tarBytes = encodeTar(options: tarOptions);
    return BZip2PlusCodec.encodeBytes(tarBytes, options: bzip2Options);
  }
}

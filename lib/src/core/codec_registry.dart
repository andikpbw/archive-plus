import 'dart:typed_data';

import 'archive.dart';
import 'archive_security.dart';

/// Contract for pluggable single-stream compression codecs registered with
/// [ArchiveCodecRegistry].
abstract interface class ArchiveCompressionCodec {
  /// Unique lowercase codec identifier (for example, `'gzip'`, `'lz4'`,
  /// `'my-rle'`).
  String get name;

  /// Compresses raw [input] bytes.
  Uint8List compress(Uint8List input);

  /// Decompresses [input] bytes while enforcing [securityPolicy].
  Uint8List decompress(
    Uint8List input, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  });
}

/// Contract for pluggable multi-entry container format codecs registered with
/// [ArchiveCodecRegistry].
abstract interface class ArchiveFormatCodec {
  /// Unique lowercase format identifier (for example, `'zip'`, `'tar'`,
  /// `'pak'`).
  String get name;

  /// Canonical file extensions without leading dot (for example, `['zip']`).
  List<String> get extensions;

  /// Returns `true` if [bytes] begins with or matches this format's signature.
  bool canDecode(Uint8List bytes);

  /// Encodes an [Archive] into raw bytes.
  Uint8List encode(Archive archive);

  /// Decodes raw [bytes] into an [Archive] while enforcing [securityPolicy].
  Archive decode(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  });
}

/// Extensible registry allowing applications to customize, override, or add
/// compression algorithms and archive container formats.
final class ArchiveCodecRegistry {
  /// Creates an empty [ArchiveCodecRegistry].
  ArchiveCodecRegistry();

  final Map<String, ArchiveCompressionCodec> _compressionCodecs =
      <String, ArchiveCompressionCodec>{};
  final Map<String, ArchiveFormatCodec> _formatCodecs =
      <String, ArchiveFormatCodec>{};

  /// Registers or overrides a compression codec by [ArchiveCompressionCodec.name].
  void registerCompression(ArchiveCompressionCodec codec) {
    _compressionCodecs[codec.name.toLowerCase()] = codec;
  }

  /// Registers or overrides an archive format codec by [ArchiveFormatCodec.name].
  void registerFormat(ArchiveFormatCodec codec) {
    _formatCodecs[codec.name.toLowerCase()] = codec;
  }

  /// Removes a previously registered compression codec.
  ArchiveCompressionCodec? unregisterCompression(String name) {
    return _compressionCodecs.remove(name.toLowerCase());
  }

  /// Removes a previously registered format codec.
  ArchiveFormatCodec? unregisterFormat(String name) {
    return _formatCodecs.remove(name.toLowerCase());
  }

  /// Looks up a compression codec by [name], or `null` if not registered.
  ArchiveCompressionCodec? compression(String name) {
    return _compressionCodecs[name.toLowerCase()];
  }

  /// Looks up a format codec by [name], or `null` if not registered.
  ArchiveFormatCodec? format(String name) {
    return _formatCodecs[name.toLowerCase()];
  }

  /// Detects the first registered [ArchiveFormatCodec] capable of decoding
  /// [bytes], or returns `null`.
  ArchiveFormatCodec? detectFormat(Uint8List bytes) {
    for (final codec in _formatCodecs.values) {
      if (codec.canDecode(bytes)) {
        return codec;
      }
    }
    return null;
  }

  /// Registered compression codec names.
  Iterable<String> get compressionNames => _compressionCodecs.keys;

  /// Registered format codec names.
  Iterable<String> get formatNames => _formatCodecs.keys;
}

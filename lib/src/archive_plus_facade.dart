import 'dart:typed_data';

import 'codecs/bzip2_codec.dart';
import 'codecs/gzip_codec.dart';
import 'codecs/lz4_codec.dart';
import 'codecs/zlib_codec.dart';
import 'core/archive.dart';
import 'core/archive_builder.dart';
import 'core/archive_exceptions.dart';
import 'core/archive_filter.dart';
import 'core/archive_format.dart';
import 'core/archive_options.dart';
import 'core/archive_progress.dart';
import 'core/archive_security.dart';
import 'core/codec_registry.dart';
import 'formats/tar/tar_decoder.dart';
import 'formats/tar/tar_encoder.dart';
import 'formats/zip/zip_decoder.dart';
import 'formats/zip/zip_encoder.dart';
import 'formats/zip/zip_metadata.dart';
import 'util/byte_buffer.dart';

/// Unified high-level entry point for creating, inspecting, compressing, and
/// extracting archives across ZIP, TAR, TAR.GZ, TAR.BZ2, GZIP, ZLIB, DEFLATE,
/// BZip2, and LZ4 formats.
final class ArchivePlus {
  ArchivePlus._();

  /// Creates a fluent [ArchiveBuilder] for assembling archives with method
  /// chaining.
  static ArchiveBuilder builder() => ArchiveBuilder();

  /// Creates an [ArchiveCodecRegistry] pre-populated with all built-in
  /// compression and container format codecs.
  static ArchiveCodecRegistry defaultRegistry() {
    return ArchiveCodecRegistry()
      ..registerCompression(_DeflateRegistryCodec())
      ..registerCompression(_ZLibRegistryCodec())
      ..registerCompression(_GZipRegistryCodec())
      ..registerCompression(_BZip2RegistryCodec())
      ..registerCompression(_Lz4RegistryCodec())
      ..registerFormat(_ZipRegistryFormat())
      ..registerFormat(_TarRegistryFormat())
      ..registerFormat(_TarGzRegistryFormat())
      ..registerFormat(_TarBz2RegistryFormat());
  }

  // ---------------------------------------------------------------------------
  // Format Detection & Auto Decoding
  // ---------------------------------------------------------------------------

  /// Detects the archive or compression format of [bytes] using magic headers
  /// and an optional [fileName] extension hint.
  static ArchiveFormat detectFormat(List<int> bytes, {String? fileName}) {
    return ArchiveFormatDetector.detect(bytes, fileName: fileName);
  }

  /// Automatically detects and decodes a ZIP, TAR, TAR.GZ, or TAR.BZ2 archive.
  ///
  /// When [bytes] is a GZIP or BZip2 stream without a `.tar.*` filename hint,
  /// this method decompresses the outer stream and inspects whether the inner
  /// payload is a TAR archive; if not, it wraps the decoded payload as a single
  /// file entry inside an [Archive].
  static Archive decodeAuto(
    List<int> bytes, {
    String? fileName,
    String? password,
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
    ArchiveFilter? filter,
    ArchiveProgressCallback? onProgress,
    ArchiveCancelToken? cancelToken,
  }) {
    final format = detectFormat(bytes, fileName: fileName);
    switch (format) {
      case ArchiveFormat.zip:
        return unzip(
          bytes,
          options: ZipDecodeOptions(
            password: password,
            securityPolicy: securityPolicy,
            filter: filter,
            onProgress: onProgress,
            cancelToken: cancelToken,
          ),
        );
      case ArchiveFormat.tar:
        return untar(
          bytes,
          options: TarDecodeOptions(
            securityPolicy: securityPolicy,
            filter: filter,
            onProgress: onProgress,
            cancelToken: cancelToken,
          ),
        );
      case ArchiveFormat.tarGz:
        return untarGz(
          bytes,
          gzipOptions: GZipOptions(securityPolicy: securityPolicy),
          tarOptions: TarDecodeOptions(
            securityPolicy: securityPolicy,
            filter: filter,
            onProgress: onProgress,
            cancelToken: cancelToken,
          ),
        );
      case ArchiveFormat.tarBz2:
        return untarBz2(
          bytes,
          bzip2Options: BZip2Options(securityPolicy: securityPolicy),
          tarOptions: TarDecodeOptions(
            securityPolicy: securityPolicy,
            filter: filter,
            onProgress: onProgress,
            cancelToken: cancelToken,
          ),
        );
      case ArchiveFormat.gzip:
        final decoded = gunzipWithMetadata(
          bytes,
          options: GZipOptions(securityPolicy: securityPolicy),
        );
        if (detectFormat(decoded.bytes) == ArchiveFormat.tar) {
          return untar(
            decoded.bytes,
            options: TarDecodeOptions(
              securityPolicy: securityPolicy,
              filter: filter,
              onProgress: onProgress,
              cancelToken: cancelToken,
            ),
          );
        }
        final entryName = _stripExtension(
          decoded.metadata.filename ?? fileName ?? 'payload.bin',
          '.gz',
        );
        return Archive(
          entries: <ArchiveEntry>[
            ArchiveEntry.file(
              securityPolicy.sanitizePath(entryName),
              decoded.bytes,
              modifiedTime: decoded.metadata.modifiedTime,
              comment: decoded.metadata.comment,
            ),
          ],
        );
      case ArchiveFormat.bzip2:
        final decoded = bunzip2(
          bytes,
          options: BZip2Options(securityPolicy: securityPolicy),
        );
        if (detectFormat(decoded) == ArchiveFormat.tar) {
          return untar(
            decoded,
            options: TarDecodeOptions(
              securityPolicy: securityPolicy,
              filter: filter,
              onProgress: onProgress,
              cancelToken: cancelToken,
            ),
          );
        }
        final entryName = _stripExtension(fileName ?? 'payload.bin', '.bz2');
        return Archive(
          entries: <ArchiveEntry>[
            ArchiveEntry.file(securityPolicy.sanitizePath(entryName), decoded),
          ],
        );
      case ArchiveFormat.lz4:
        final decoded = unlz4(
          bytes,
          options: Lz4Options(securityPolicy: securityPolicy),
        );
        final entryName = _stripExtension(fileName ?? 'payload.bin', '.lz4');
        return Archive(
          entries: <ArchiveEntry>[
            ArchiveEntry.file(securityPolicy.sanitizePath(entryName), decoded),
          ],
        );
      case ArchiveFormat.zlib:
        final decoded = unzlib(
          bytes,
          options: ZLibOptions(securityPolicy: securityPolicy),
        );
        final entryName = _stripExtension(fileName ?? 'payload.bin', '.zlib');
        return Archive(
          entries: <ArchiveEntry>[
            ArchiveEntry.file(securityPolicy.sanitizePath(entryName), decoded),
          ],
        );
      case ArchiveFormat.unknown:
        throw const ArchiveFormatException(
          'Unable to detect a supported archive or compression format.',
        );
    }
  }

  // ---------------------------------------------------------------------------
  // ZIP Operations
  // ---------------------------------------------------------------------------

  /// Encodes an [Archive] into PKWARE ZIP bytes.
  static Uint8List zip(
    Archive archive, {
    ZipEncodeOptions options = const ZipEncodeOptions(),
  }) {
    return ZipEncoder.encode(archive, options: options);
  }

  /// Decodes PKWARE ZIP [bytes] into an [Archive].
  static Archive unzip(
    List<int> bytes, {
    ZipDecodeOptions options = const ZipDecodeOptions(),
  }) {
    return ZipDecoder.decode(bytes, options: options);
  }

  /// Inspects a ZIP archive's Central Directory without decompressing any
  /// entry payloads.
  static ZipArchiveSummary inspectZip(
    List<int> bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) {
    return ZipDecoder.inspect(bytes, securityPolicy: securityPolicy);
  }

  /// Selectively extracts a single entry named [entryName] from a ZIP buffer
  /// without decompressing other entries.
  static ArchiveEntry? extractZipEntry(
    List<int> bytes,
    String entryName, {
    ZipDecodeOptions options = const ZipDecodeOptions(),
  }) {
    return ZipDecoder.extractEntry(bytes, entryName, options: options);
  }

  // ---------------------------------------------------------------------------
  // TAR, TAR.GZ & TAR.BZ2 Operations
  // ---------------------------------------------------------------------------

  /// Encodes an [Archive] into POSIX USTAR / PAX TAR bytes.
  static Uint8List tar(
    Archive archive, {
    TarEncodeOptions options = const TarEncodeOptions(),
  }) {
    return TarEncoder.encode(archive, options: options);
  }

  /// Decodes POSIX USTAR / PAX / GNU TAR [bytes] into an [Archive].
  static Archive untar(
    List<int> bytes, {
    TarDecodeOptions options = const TarDecodeOptions(),
  }) {
    return TarDecoder.decode(bytes, options: options);
  }

  /// Encodes an [Archive] into a GZIP-compressed `.tar.gz` byte buffer.
  static Uint8List tarGz(
    Archive archive, {
    TarEncodeOptions tarOptions = const TarEncodeOptions(),
    GZipOptions gzipOptions = const GZipOptions(),
  }) {
    final tarBytes = TarEncoder.encode(archive, options: tarOptions);
    return GZipPlusCodec.encodeBytes(tarBytes, options: gzipOptions);
  }

  /// Decodes a `.tar.gz` / `.tgz` byte buffer into an [Archive].
  static Archive untarGz(
    List<int> bytes, {
    GZipOptions gzipOptions = const GZipOptions(),
    TarDecodeOptions tarOptions = const TarDecodeOptions(),
  }) {
    final tarBytes = GZipPlusCodec.decodeBytes(bytes, options: gzipOptions);
    return TarDecoder.decode(tarBytes, options: tarOptions);
  }

  /// Encodes an [Archive] into a BZip2-compressed `.tar.bz2` byte buffer.
  static Uint8List tarBz2(
    Archive archive, {
    TarEncodeOptions tarOptions = const TarEncodeOptions(),
    BZip2Options bzip2Options = const BZip2Options(),
  }) {
    final tarBytes = TarEncoder.encode(archive, options: tarOptions);
    return BZip2PlusCodec.encodeBytes(tarBytes, options: bzip2Options);
  }

  /// Decodes a `.tar.bz2` / `.tbz2` byte buffer into an [Archive].
  static Archive untarBz2(
    List<int> bytes, {
    BZip2Options bzip2Options = const BZip2Options(),
    TarDecodeOptions tarOptions = const TarDecodeOptions(),
  }) {
    final tarBytes = BZip2PlusCodec.decodeBytes(bytes, options: bzip2Options);
    return TarDecoder.decode(tarBytes, options: tarOptions);
  }

  // ---------------------------------------------------------------------------
  // Single-Stream Compression Codecs
  // ---------------------------------------------------------------------------

  /// Compresses [bytes] using RFC 1952 GZIP.
  static Uint8List gzip(
    List<int> bytes, {
    GZipOptions options = const GZipOptions(),
  }) {
    return GZipPlusCodec.encodeBytes(bytes, options: options);
  }

  /// Decompresses RFC 1952 GZIP [bytes].
  static Uint8List gunzip(
    List<int> bytes, {
    GZipOptions options = const GZipOptions(),
  }) {
    return GZipPlusCodec.decodeBytes(bytes, options: options);
  }

  /// Decompresses RFC 1952 GZIP [bytes] and returns both payload and header
  /// [GZipMetadata].
  static GZipDecodedResult gunzipWithMetadata(
    List<int> bytes, {
    GZipOptions options = const GZipOptions(),
  }) {
    return GZipPlusCodec.decodeWithMetadata(bytes, options: options);
  }

  /// Compresses [bytes] using RFC 1950 ZLIB.
  static Uint8List zlib(
    List<int> bytes, {
    ZLibOptions options = const ZLibOptions(),
  }) {
    return ZLibPlusCodec.encodeBytes(bytes, options: options);
  }

  /// Decompresses RFC 1950 ZLIB [bytes].
  static Uint8List unzlib(
    List<int> bytes, {
    ZLibOptions options = const ZLibOptions(),
  }) {
    return ZLibPlusCodec.decodeBytes(bytes, options: options);
  }

  /// Compresses [bytes] using raw RFC 1951 DEFLATE.
  static Uint8List deflate(
    List<int> bytes, {
    CompressionLevel level = CompressionLevel.balanced,
  }) {
    return DeflatePlusCodec.encodeBytes(bytes, level: level);
  }

  /// Decompresses raw RFC 1951 DEFLATE [bytes].
  static Uint8List inflate(
    List<int> bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) {
    return DeflatePlusCodec.decodeBytes(bytes, securityPolicy: securityPolicy);
  }

  /// Compresses [bytes] using BZip2.
  static Uint8List bzip2(
    List<int> bytes, {
    BZip2Options options = const BZip2Options(),
  }) {
    return BZip2PlusCodec.encodeBytes(bytes, options: options);
  }

  /// Decompresses BZip2 [bytes].
  static Uint8List bunzip2(
    List<int> bytes, {
    BZip2Options options = const BZip2Options(),
  }) {
    return BZip2PlusCodec.decodeBytes(bytes, options: options);
  }

  /// Compresses [bytes] using the LZ4 Frame Format.
  static Uint8List lz4(
    List<int> bytes, {
    Lz4Options options = const Lz4Options(),
  }) {
    return Lz4PlusCodec.encodeBytes(bytes, options: options);
  }

  /// Decompresses LZ4 Frame Format [bytes].
  static Uint8List unlz4(
    List<int> bytes, {
    Lz4Options options = const Lz4Options(),
  }) {
    return Lz4PlusCodec.decodeBytes(bytes, options: options);
  }

  static String _stripExtension(String name, String suffix) {
    final normalized = name.replaceAll('\\', '/');
    final base = normalized.contains('/')
        ? normalized.substring(normalized.lastIndexOf('/') + 1)
        : normalized;
    if (base.toLowerCase().endsWith(suffix) && base.length > suffix.length) {
      return base.substring(0, base.length - suffix.length);
    }
    return base.isEmpty ? 'payload.bin' : base;
  }
}

// -----------------------------------------------------------------------------
// Built-in Registry Adapters
// -----------------------------------------------------------------------------

final class _DeflateRegistryCodec implements ArchiveCompressionCodec {
  @override
  String get name => 'deflate';

  @override
  Uint8List compress(Uint8List input) => DeflatePlusCodec.encodeBytes(input);

  @override
  Uint8List decompress(
    Uint8List input, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) => DeflatePlusCodec.decodeBytes(input, securityPolicy: securityPolicy);
}

final class _ZLibRegistryCodec implements ArchiveCompressionCodec {
  @override
  String get name => 'zlib';

  @override
  Uint8List compress(Uint8List input) => ZLibPlusCodec.encodeBytes(input);

  @override
  Uint8List decompress(
    Uint8List input, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) => ZLibPlusCodec.decodeBytes(
    input,
    options: ZLibOptions(securityPolicy: securityPolicy),
  );
}

final class _GZipRegistryCodec implements ArchiveCompressionCodec {
  @override
  String get name => 'gzip';

  @override
  Uint8List compress(Uint8List input) => GZipPlusCodec.encodeBytes(input);

  @override
  Uint8List decompress(
    Uint8List input, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) => GZipPlusCodec.decodeBytes(
    input,
    options: GZipOptions(securityPolicy: securityPolicy),
  );
}

final class _BZip2RegistryCodec implements ArchiveCompressionCodec {
  @override
  String get name => 'bzip2';

  @override
  Uint8List compress(Uint8List input) => BZip2PlusCodec.encodeBytes(input);

  @override
  Uint8List decompress(
    Uint8List input, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) => BZip2PlusCodec.decodeBytes(
    input,
    options: BZip2Options(securityPolicy: securityPolicy),
  );
}

final class _Lz4RegistryCodec implements ArchiveCompressionCodec {
  @override
  String get name => 'lz4';

  @override
  Uint8List compress(Uint8List input) => Lz4PlusCodec.encodeBytes(input);

  @override
  Uint8List decompress(
    Uint8List input, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) => Lz4PlusCodec.decodeBytes(
    input,
    options: Lz4Options(securityPolicy: securityPolicy),
  );
}

final class _ZipRegistryFormat implements ArchiveFormatCodec {
  @override
  String get name => 'zip';

  @override
  List<String> get extensions => const <String>['zip'];

  @override
  bool canDecode(Uint8List bytes) =>
      ArchiveFormatDetector.detect(bytes) == ArchiveFormat.zip;

  @override
  Uint8List encode(Archive archive) => ZipEncoder.encode(archive);

  @override
  Archive decode(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) => ZipDecoder.decode(
    bytes,
    options: ZipDecodeOptions(securityPolicy: securityPolicy),
  );
}

final class _TarRegistryFormat implements ArchiveFormatCodec {
  @override
  String get name => 'tar';

  @override
  List<String> get extensions => const <String>['tar'];

  @override
  bool canDecode(Uint8List bytes) =>
      ArchiveFormatDetector.detect(bytes) == ArchiveFormat.tar;

  @override
  Uint8List encode(Archive archive) => TarEncoder.encode(archive);

  @override
  Archive decode(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) => TarDecoder.decode(
    bytes,
    options: TarDecodeOptions(securityPolicy: securityPolicy),
  );
}

final class _TarGzRegistryFormat implements ArchiveFormatCodec {
  @override
  String get name => 'tar.gz';

  @override
  List<String> get extensions => const <String>['tar.gz', 'tgz'];

  @override
  bool canDecode(Uint8List bytes) =>
      ArchiveFormatDetector.detect(bytes) == ArchiveFormat.gzip;

  @override
  Uint8List encode(Archive archive) => ArchivePlus.tarGz(archive);

  @override
  Archive decode(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) => ArchivePlus.untarGz(
    bytes,
    gzipOptions: GZipOptions(securityPolicy: securityPolicy),
    tarOptions: TarDecodeOptions(securityPolicy: securityPolicy),
  );
}

final class _TarBz2RegistryFormat implements ArchiveFormatCodec {
  @override
  String get name => 'tar.bz2';

  @override
  List<String> get extensions => const <String>['tar.bz2', 'tbz2'];

  @override
  bool canDecode(Uint8List bytes) =>
      ArchiveFormatDetector.detect(bytes) == ArchiveFormat.bzip2;

  @override
  Uint8List encode(Archive archive) => ArchivePlus.tarBz2(archive);

  @override
  Archive decode(
    Uint8List bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) => ArchivePlus.untarBz2(
    bytes,
    bzip2Options: BZip2Options(securityPolicy: securityPolicy),
    tarOptions: TarDecodeOptions(securityPolicy: securityPolicy),
  );
}

/// Extension helpers converting raw `List<int>` buffers into [Uint8List].
extension ArchiveByteListExtension on List<int> {
  /// Returns this list as a [Uint8List] without copying when possible.
  Uint8List toUint8List() => asUint8List(this);
}

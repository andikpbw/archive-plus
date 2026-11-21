/// Modern, lightweight, zero-dependency archive and compression library for
/// Dart and Flutter.
///
/// Works seamlessly across **Android, iOS, macOS, Windows, Linux, Web, and
/// WebAssembly (Wasm)** with support for:
///
/// - **Containers:** ZIP (Store, DEFLATE, BZip2, ZIP64, UTF-8, ZipCrypto
///   encryption, zero-decompression Central Directory inspection, selective
///   single-entry extraction) and TAR (POSIX USTAR, PAX Extended Headers, GNU
///   LongName/LongLink), plus `.tar.gz` and `.tar.bz2`.
/// - **Compression Codecs:** Raw DEFLATE (RFC 1951), ZLIB (RFC 1950), GZIP
///   (RFC 1952 with metadata & multi-member support), BZip2, and LZ4 Frame
///   Format — all available as both one-liners and `dart:convert` codecs.
/// - **Security First:** Built-in `ArchiveSecurityPolicy` guarding against
///   Zip-Slip path traversal, Zip-Bomb ratio/size exhaustion, symlink escapes,
///   and checksum tampering, with exhaustive Dart 3 `sealed`
///   `ArchiveException` types.
/// - **Customizable & Observable:** Fluent `ArchiveBuilder`, glob-based
///   `ArchiveFilter`, live `ArchiveProgress` telemetry, `ArchiveCancelToken`,
///   `Archive.diff`, and an extensible `ArchiveCodecRegistry`.
///
/// For native file-system extraction/compression and background isolate
/// execution, import `package:archive_plus/archive_plus_io.dart`.
library;

export 'src/archive_plus_facade.dart';
export 'src/codecs/bzip2_codec.dart';
export 'src/codecs/gzip_codec.dart';
export 'src/codecs/lz4_codec.dart';
export 'src/codecs/zlib_codec.dart';
export 'src/core/archive.dart';
export 'src/core/archive_builder.dart';
export 'src/core/archive_exceptions.dart';
export 'src/core/archive_filter.dart';
export 'src/core/archive_format.dart';
export 'src/core/archive_options.dart';
export 'src/core/archive_progress.dart';
export 'src/core/archive_security.dart';
export 'src/core/codec_registry.dart';
export 'src/formats/tar/tar_decoder.dart';
export 'src/formats/tar/tar_encoder.dart';
export 'src/formats/zip/zip_decoder.dart';
export 'src/formats/zip/zip_encoder.dart';
export 'src/formats/zip/zip_metadata.dart';
export 'src/util/checksums.dart';
export 'src/util/path_sanitizer.dart';

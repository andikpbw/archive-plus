import 'archive_filter.dart';
import 'archive_progress.dart';
import 'archive_security.dart';

/// Standard compression effort presets from `0` (store only) to `9` (best).
enum CompressionLevel {
  /// No compression (store raw bytes directly).
  none(0),

  /// Fastest compression with minimal CPU effort.
  fastest(1),

  /// Fast compression with good speed-to-ratio trade-off.
  fast(3),

  /// Balanced default compression level (equivalent to zlib level 6).
  balanced(6),

  /// High compression effort for smaller payloads.
  high(8),

  /// Maximum compression effort.
  best(9);

  const CompressionLevel(this.level);

  /// Numeric compression level (`0`..`9`).
  final int level;
}

/// Compression algorithm used for individual archive entries.
enum CompressionMethod {
  /// Uncompressed raw storage (ZIP method 0).
  store(0),

  /// RFC 1951 DEFLATE compression (ZIP method 8).
  deflate(8),

  /// BZip2 compression (ZIP method 12).
  bzip2(12);

  const CompressionMethod(this.zipCode);

  /// PKWARE ZIP compression method identifier.
  final int zipCode;

  /// Resolves a [CompressionMethod] from its PKWARE [zipCode], or returns
  /// `null` if unsupported.
  static CompressionMethod? fromZipCode(int zipCode) {
    return switch (zipCode) {
      0 => CompressionMethod.store,
      8 => CompressionMethod.deflate,
      12 => CompressionMethod.bzip2,
      _ => null,
    };
  }
}

/// Configuration options for encoding a ZIP archive.
final class ZipEncodeOptions {
  /// Creates [ZipEncodeOptions].
  const ZipEncodeOptions({
    this.level = CompressionLevel.balanced,
    this.method = CompressionMethod.deflate,
    this.autoStoreIfLarger = true,
    this.password,
    this.comment,
    this.useUtf8 = true,
    this.includeExtendedTimestamp = true,
    this.forceZip64 = false,
    this.filter,
    this.onProgress,
    this.cancelToken,
  });

  /// Compression effort level (0..9).
  final CompressionLevel level;

  /// Default compression method for entries without an explicit override.
  final CompressionMethod method;

  /// Automatically stores an entry uncompressed when compression yields a
  /// larger payload (e.g., already-compressed PNG/JPEG/MP4 files).
  final bool autoStoreIfLarger;

  /// Optional password enabling Traditional PKWARE ZipCrypto encryption.
  final String? password;

  /// Optional archive-level comment written to the End of Central Directory.
  final String? comment;

  /// Sets the UTF-8 EFS flag (General Purpose Bit 11) for modern Unicode
  /// filenames and comments.
  final bool useUtf8;

  /// Writes the `0x5455` Extended Timestamp extra field for exact UTC times.
  final bool includeExtendedTimestamp;

  /// Forces ZIP64 records even when entry counts and sizes fit in 32 bits.
  final bool forceZip64;

  /// Optional filter selecting which entries to include in the ZIP output.
  final ArchiveFilter? filter;

  /// Optional progress callback.
  final ArchiveProgressCallback? onProgress;

  /// Optional cooperative cancellation token.
  final ArchiveCancelToken? cancelToken;
}

/// Configuration options for decoding a ZIP archive.
final class ZipDecodeOptions {
  /// Creates [ZipDecodeOptions].
  const ZipDecodeOptions({
    this.password,
    this.securityPolicy = ArchiveSecurityPolicy.standard,
    this.filter,
    this.onProgress,
    this.cancelToken,
  });

  /// Optional password for decrypting ZipCrypto-encrypted entries.
  final String? password;

  /// Security guard policy enforced during decoding.
  final ArchiveSecurityPolicy securityPolicy;

  /// Optional filter selecting which entries to decompress and return.
  final ArchiveFilter? filter;

  /// Optional progress callback.
  final ArchiveProgressCallback? onProgress;

  /// Optional cooperative cancellation token.
  final ArchiveCancelToken? cancelToken;
}

/// Configuration options for encoding a TAR archive.
final class TarEncodeOptions {
  /// Creates [TarEncodeOptions].
  const TarEncodeOptions({
    this.usePaxHeaders = true,
    this.defaultFilePermissions = 0x1a4, // 0644
    this.defaultDirectoryPermissions = 0x1ed, // 0755
    this.filter,
    this.onProgress,
    this.cancelToken,
  });

  /// Automatically emits POSIX PAX extended headers (`x`) for paths longer
  /// than 100 bytes, non-ASCII UTF-8 paths, large sizes, or custom metadata.
  final bool usePaxHeaders;

  /// Default UNIX permission bits for regular files (`0644`).
  final int defaultFilePermissions;

  /// Default UNIX permission bits for directories (`0755`).
  final int defaultDirectoryPermissions;

  /// Optional filter selecting which entries to archive.
  final ArchiveFilter? filter;

  /// Optional progress callback.
  final ArchiveProgressCallback? onProgress;

  /// Optional cooperative cancellation token.
  final ArchiveCancelToken? cancelToken;
}

/// Configuration options for decoding a TAR archive.
final class TarDecodeOptions {
  /// Creates [TarDecodeOptions].
  const TarDecodeOptions({
    this.securityPolicy = ArchiveSecurityPolicy.standard,
    this.filter,
    this.onProgress,
    this.cancelToken,
  });

  /// Security guard policy enforced during TAR parsing.
  final ArchiveSecurityPolicy securityPolicy;

  /// Optional filter selecting which entries to keep.
  final ArchiveFilter? filter;

  /// Optional progress callback.
  final ArchiveProgressCallback? onProgress;

  /// Optional cooperative cancellation token.
  final ArchiveCancelToken? cancelToken;
}

/// Configuration options for GZIP compression and decompression.
final class GZipOptions {
  /// Creates [GZipOptions].
  const GZipOptions({
    this.level = CompressionLevel.balanced,
    this.filename,
    this.comment,
    this.modifiedTime,
    this.extra,
    this.includeHeaderCrc = false,
    this.securityPolicy = ArchiveSecurityPolicy.standard,
  });

  /// Compression level for encoding.
  final CompressionLevel level;

  /// Optional original filename stored in the GZIP `FNAME` header.
  final String? filename;

  /// Optional comment stored in the GZIP `FCOMMENT` header.
  final String? comment;

  /// Optional modification timestamp stored in the GZIP `MTIME` header.
  final DateTime? modifiedTime;

  /// Optional extra bytes stored in the GZIP `FEXTRA` field.
  final List<int>? extra;

  /// Whether to write the optional 16-bit header CRC (`FHCRC`).
  final bool includeHeaderCrc;

  /// Security policy enforced when decoding.
  final ArchiveSecurityPolicy securityPolicy;
}

/// Configuration options for ZLIB compression and decompression.
final class ZLibOptions {
  /// Creates [ZLibOptions].
  const ZLibOptions({
    this.level = CompressionLevel.balanced,
    this.securityPolicy = ArchiveSecurityPolicy.standard,
  });

  /// Compression level for encoding.
  final CompressionLevel level;

  /// Security policy enforced when decoding.
  final ArchiveSecurityPolicy securityPolicy;
}

/// Configuration options for BZip2 compression and decompression.
final class BZip2Options {
  /// Creates [BZip2Options].
  const BZip2Options({
    this.blockSize100k = 9,
    this.securityPolicy = ArchiveSecurityPolicy.standard,
  }) : assert(
         blockSize100k >= 1 && blockSize100k <= 9,
         'blockSize100k must be between 1 and 9.',
       );

  /// BZip2 block size in increments of 100,000 bytes (`1`..`9`).
  final int blockSize100k;

  /// Security policy enforced when decoding.
  final ArchiveSecurityPolicy securityPolicy;
}

/// Maximum block sizes supported by the LZ4 Frame Format.
enum Lz4BlockSize {
  /// 64 KiB blocks (BD code 4).
  kb64(4, 64 * 1024),

  /// 256 KiB blocks (BD code 5).
  kb256(5, 256 * 1024),

  /// 1 MiB blocks (BD code 6).
  mb1(6, 1024 * 1024),

  /// 4 MiB blocks (BD code 7).
  mb4(7, 4 * 1024 * 1024);

  const Lz4BlockSize(this.id, this.maxBytes);

  /// LZ4 Frame block-size identifier (`4`..`7`).
  final int id;

  /// Maximum uncompressed bytes per block.
  final int maxBytes;

  /// Looks up an [Lz4BlockSize] from its frame header [id].
  static Lz4BlockSize? fromId(int id) {
    return switch (id) {
      4 => Lz4BlockSize.kb64,
      5 => Lz4BlockSize.kb256,
      6 => Lz4BlockSize.mb1,
      7 => Lz4BlockSize.mb4,
      _ => null,
    };
  }
}

/// Configuration options for LZ4 Frame Format compression and decompression.
final class Lz4Options {
  /// Creates [Lz4Options].
  const Lz4Options({
    this.blockSize = Lz4BlockSize.mb4,
    this.blockChecksum = false,
    this.contentChecksum = true,
    this.includeContentSize = true,
    this.securityPolicy = ArchiveSecurityPolicy.standard,
  });

  /// Maximum uncompressed block size per LZ4 frame block.
  final Lz4BlockSize blockSize;

  /// Whether to append a 32-bit XXH32 checksum to each individual block.
  final bool blockChecksum;

  /// Whether to append a 32-bit XXH32 content checksum at the end of the frame.
  final bool contentChecksum;

  /// Whether to write the 8-byte original uncompressed size in the frame header.
  final bool includeContentSize;

  /// Security policy enforced when decoding.
  final ArchiveSecurityPolicy securityPolicy;
}

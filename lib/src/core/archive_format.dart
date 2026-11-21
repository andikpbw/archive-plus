/// Archive and compression formats recognized by `archive_plus`.
enum ArchiveFormat {
  /// PKWARE ZIP archive (`.zip`, `.jar`, `.apk`, `.docx`, `.xlsx`).
  zip,

  /// POSIX USTAR / PAX / GNU TAR archive (`.tar`).
  tar,

  /// GZIP-compressed TAR archive (`.tar.gz`, `.tgz`).
  tarGz,

  /// BZip2-compressed TAR archive (`.tar.bz2`, `.tbz2`).
  tarBz2,

  /// RFC 1952 GZIP stream (`.gz`).
  gzip,

  /// RFC 1950 ZLIB stream (`.zlib`, `.zz`).
  zlib,

  /// BZip2 stream (`.bz2`).
  bzip2,

  /// LZ4 Frame Format stream (`.lz4`).
  lz4,

  /// Unrecognized or raw uncompressed data.
  unknown,
}

/// Magic-byte and filename-hint detector for archive and compression formats.
final class ArchiveFormatDetector {
  ArchiveFormatDetector._();

  /// Inspects magic headers in [bytes] (and optional [fileName] extension hint)
  /// to determine the [ArchiveFormat].
  static ArchiveFormat detect(List<int> bytes, {String? fileName}) {
    final lowerName = fileName?.toLowerCase();

    // ZIP: PK\x03\x04 (local header), PK\x05\x06 (empty archive EOCD), PK\x07\x08.
    if (bytes.length >= 4 &&
        bytes[0] == 0x50 &&
        bytes[1] == 0x4b &&
        ((bytes[2] == 0x03 && bytes[3] == 0x04) ||
            (bytes[2] == 0x05 && bytes[3] == 0x06) ||
            (bytes[2] == 0x07 && bytes[3] == 0x08))) {
      return ArchiveFormat.zip;
    }

    // GZIP / TAR.GZ: 0x1F 0x8B 0x08
    if (bytes.length >= 3 &&
        bytes[0] == 0x1f &&
        bytes[1] == 0x8b &&
        bytes[2] == 0x08) {
      if (lowerName != null &&
          (lowerName.endsWith('.tar.gz') || lowerName.endsWith('.tgz'))) {
        return ArchiveFormat.tarGz;
      }
      return ArchiveFormat.gzip;
    }

    // BZip2 / TAR.BZ2: "BZh" followed by block size '1'..'9'
    if (bytes.length >= 4 &&
        bytes[0] == 0x42 &&
        bytes[1] == 0x5a &&
        bytes[2] == 0x68 &&
        bytes[3] >= 0x31 &&
        bytes[3] <= 0x39) {
      if (lowerName != null &&
          (lowerName.endsWith('.tar.bz2') || lowerName.endsWith('.tbz2'))) {
        return ArchiveFormat.tarBz2;
      }
      return ArchiveFormat.bzip2;
    }

    // LZ4 Frame Format: 0x04 0x22 0x4D 0x18 (little-endian 0x184D2204)
    if (bytes.length >= 4 &&
        bytes[0] == 0x04 &&
        bytes[1] == 0x22 &&
        bytes[2] == 0x4d &&
        bytes[3] == 0x18) {
      return ArchiveFormat.lz4;
    }

    // POSIX USTAR TAR: "ustar" at offset 257
    if (bytes.length >= 263 &&
        bytes[257] == 0x75 &&
        bytes[258] == 0x73 &&
        bytes[259] == 0x74 &&
        bytes[260] == 0x61 &&
        bytes[261] == 0x72) {
      return ArchiveFormat.tar;
    }

    // Check valid TAR header checksum even for legacy V7 tar archives.
    if (bytes.length >= 512 && _looksLikeTarHeader(bytes)) {
      return ArchiveFormat.tar;
    }

    // RFC 1950 ZLIB header check: CM=8, CINFO<=7, (CMF*256 + FLG) % 31 == 0
    if (bytes.length >= 6) {
      final cmf = bytes[0];
      final flg = bytes[1];
      if ((cmf & 0x0f) == 8 &&
          (cmf >>> 4) <= 7 &&
          ((cmf << 8) | flg) % 31 == 0) {
        return ArchiveFormat.zlib;
      }
    }

    return ArchiveFormat.unknown;
  }

  static bool _looksLikeTarHeader(List<int> bytes) {
    // Reject all-zero blocks.
    var hasNonZero = false;
    for (var i = 0; i < 512; i++) {
      if (bytes[i] != 0) {
        hasNonZero = true;
        break;
      }
    }
    if (!hasNonZero) {
      return false;
    }
    // Parse octal checksum stored at bytes[148..156].
    var recorded = 0;
    var parsedDigits = 0;
    for (var i = 148; i < 156; i++) {
      final b = bytes[i];
      if (b == 0 || b == 0x20) {
        if (parsedDigits > 0) {
          break;
        }
        continue;
      }
      if (b < 0x30 || b > 0x37) {
        return false;
      }
      recorded = (recorded << 3) | (b - 0x30);
      parsedDigits++;
    }
    if (parsedDigits == 0) {
      return false;
    }
    var sum = 0;
    for (var i = 0; i < 512; i++) {
      sum += (i >= 148 && i < 156) ? 0x20 : (bytes[i] & 0xff);
    }
    return sum == recorded;
  }
}

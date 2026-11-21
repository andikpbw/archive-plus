import 'dart:convert';
import 'dart:typed_data';

import '../../codecs/bzip2_codec.dart';
import '../../codecs/deflate/inflater.dart';
import '../../core/archive.dart';
import '../../core/archive_exceptions.dart';
import '../../core/archive_options.dart';
import '../../core/archive_progress.dart';
import '../../core/archive_security.dart';
import '../../util/byte_buffer.dart';
import '../../util/checksums.dart';
import 'zip_crypto.dart';
import 'zip_metadata.dart';

/// PKWARE APPNOTE 6.3.x compliant ZIP archive decoder with zero-decompression
/// Central Directory inspection, selective single-entry extraction, ZIP64
/// support, ZipCrypto decryption, and Zip-Slip / Zip-Bomb security guards.
final class ZipDecoder {
  ZipDecoder._();

  static const int _localHeaderSig = 0x04034b50;
  static const int _centralHeaderSig = 0x02014b50;
  static const int _zip64EocdSig = 0x06064b50;
  static const int _zip64LocatorSig = 0x07064b50;

  /// Inspects a ZIP archive's Central Directory without decompressing any
  /// entry payloads.
  static ZipArchiveSummary inspect(
    List<int> bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) {
    final input = asUint8List(bytes);
    final cd = _parseCentralDirectory(input, securityPolicy);
    return ZipArchiveSummary(
      entries: cd.records.map((r) => r.summary).toList(),
      isZip64: cd.isZip64,
      comment: cd.comment,
    );
  }

  /// Extracts a single entry matching [entryName] from [bytes] without
  /// decompressing other entries, or returns `null` if not found.
  static ArchiveEntry? extractEntry(
    List<int> bytes,
    String entryName, {
    ZipDecodeOptions options = const ZipDecodeOptions(),
  }) {
    final input = asUint8List(bytes);
    final policy = options.securityPolicy;
    final cd = _parseCentralDirectory(input, policy);
    final normalizedTarget = entryName.replaceAll('\\', '/');

    for (final rec in cd.records) {
      if (rec.summary.name == normalizedTarget) {
        return _decodeRecord(
          input: input,
          record: rec,
          options: options,
          alreadyDecodedBytes: 0,
        );
      }
    }
    return null;
  }

  /// Decodes all (or filtered) entries from a PKWARE ZIP byte buffer.
  static Archive decode(
    List<int> bytes, {
    ZipDecodeOptions options = const ZipDecodeOptions(),
  }) {
    final cancel = options.cancelToken;
    cancel?.throwIfCancelled();

    final input = asUint8List(bytes);
    final policy = options.securityPolicy;

    options.onProgress?.call(
      const ArchiveProgress(
        phase: ArchivePhase.inspecting,
        processedEntries: 0,
        totalEntries: 0,
      ),
    );

    final cd = _parseCentralDirectory(input, policy);
    final selected = options.filter == null
        ? cd.records
        : cd.records
              .where(
                (r) => options.filter!.matches(
                  r.summary.name,
                  size: r.summary.uncompressedSize,
                  isDirectory: r.summary.isDirectory,
                ),
              )
              .toList();

    final totalEntries = selected.length;
    final totalDeclaredBytes = selected.fold<int>(
      0,
      (sum, r) => sum + r.summary.uncompressedSize,
    );

    final archive = Archive(comment: cd.comment);
    var totalDecodedBytes = 0;
    var totalCompressedRead = 0;

    for (var i = 0; i < totalEntries; i++) {
      cancel?.throwIfCancelled();
      final rec = selected[i];

      options.onProgress?.call(
        ArchiveProgress(
          phase: ArchivePhase.decompressing,
          entryName: rec.summary.name,
          processedEntries: i,
          totalEntries: totalEntries,
          bytesProcessed: totalDecodedBytes,
          totalBytes: totalDeclaredBytes,
          compressedBytes: totalCompressedRead,
        ),
      );

      final entry = _decodeRecord(
        input: input,
        record: rec,
        options: options,
        alreadyDecodedBytes: totalDecodedBytes,
      );
      totalDecodedBytes += entry.size;
      totalCompressedRead += rec.summary.compressedSize;
      policy.checkTotalSize(totalDecodedBytes, entryName: entry.name);
      archive.add(entry);
    }

    options.onProgress?.call(
      ArchiveProgress(
        phase: ArchivePhase.completed,
        processedEntries: totalEntries,
        totalEntries: totalEntries,
        bytesProcessed: totalDecodedBytes,
        totalBytes: totalDecodedBytes,
        compressedBytes: totalCompressedRead,
      ),
    );

    return archive;
  }

  static ArchiveEntry _decodeRecord({
    required Uint8List input,
    required _ParsedCentralRecord record,
    required ZipDecodeOptions options,
    required int alreadyDecodedBytes,
  }) {
    final policy = options.securityPolicy;
    final summary = record.summary;

    // Pre-check declared sizes and ratio before decompressing.
    policy.checkEntrySize(summary.uncompressedSize, entryName: summary.name);
    policy.checkTotalSize(
      alreadyDecodedBytes + summary.uncompressedSize,
      entryName: summary.name,
    );
    policy.checkCompressionRatio(
      compressedSize: summary.compressedSize,
      uncompressedSize: summary.uncompressedSize,
      entryName: summary.name,
    );

    // Jump to Local File Header.
    final reader = ByteReader(input, offset: summary.localHeaderOffset);
    final sig = reader.readUint32LE();
    if (sig != _localHeaderSig) {
      throw ArchiveFormatException(
        'Invalid ZIP Local File Header signature at offset '
        '${summary.localHeaderOffset}.',
        entryName: summary.name,
        offset: summary.localHeaderOffset,
      );
    }

    reader.skip(
      22,
    ); // version(2)+flags(2)+method(2)+time(2)+date(2)+crc(4)+csize(4)+usize(4)
    final localNameLen = reader.readUint16LE();
    final localExtraLen = reader.readUint16LE();
    reader.skip(localNameLen + localExtraLen);

    var compressedPayload = reader.readBytesView(summary.compressedSize);

    if (summary.isEncrypted) {
      // Reject unsupported WinZip AES (method 99) or strong encryption (bit 6).
      if ((record.flags & 0x0040) != 0 || summary.compressionMethodCode == 99) {
        throw ArchiveFormatException(
          'Strong/AES ZIP encryption is not supported for entry.',
          entryName: summary.name,
          offset: summary.localHeaderOffset,
        );
      }
      final password = options.password;
      if (password == null || password.isEmpty) {
        throw ArchivePasswordException(
          'Entry is password-protected and no password was provided.',
          entryName: summary.name,
          offset: summary.localHeaderOffset,
        );
      }
      compressedPayload = ZipCrypto.decrypt(
        compressedPayload,
        password: password,
        crcCheckByte: (summary.crc32 >>> 24) & 0xff,
        dosTimeCheckByte: (record.dosTime >>> 8) & 0xff,
        hasDataDescriptor: (record.flags & 0x0008) != 0,
        entryName: summary.name,
      );
    }

    final maxAllowed = policy.effectiveSingleStreamLimit(
      alreadyDecoded: alreadyDecodedBytes,
    );

    final Uint8List rawBytes;
    switch (summary.compressionMethodCode) {
      case 0: // Store
        if (maxAllowed != null && compressedPayload.length > maxAllowed) {
          throw ArchiveSecurityException(
            'Stored entry size (${compressedPayload.length} bytes) exceeds '
            'policy limit ($maxAllowed bytes).',
            violation: ArchiveSecurityViolation.entrySizeLimitExceeded,
            entryName: summary.name,
          );
        }
        rawBytes = Uint8List.fromList(compressedPayload);
      case 8: // Deflate
        rawBytes = DeflateInflater.inflate(
          compressedPayload,
          maxOutputSize: maxAllowed,
          entryName: summary.name,
        );
      case 12: // BZip2
        rawBytes = BZip2PlusCodec.decodeBytes(
          compressedPayload,
          options: BZip2Options(
            securityPolicy: policy.copyWith(
              maxEntrySize: maxAllowed ?? policy.maxEntrySize,
            ),
          ),
        );
      default:
        throw ArchiveFormatException(
          'Unsupported ZIP compression method '
          '${summary.compressionMethodCode}.',
          entryName: summary.name,
          offset: summary.localHeaderOffset,
        );
    }

    // Re-check actual decoded size & compression ratio against zip bombs with
    // spoofed Central Directory headers.
    policy.checkEntrySize(rawBytes.length, entryName: summary.name);
    policy.checkTotalSize(
      alreadyDecodedBytes + rawBytes.length,
      entryName: summary.name,
    );
    policy.checkCompressionRatio(
      compressedSize: summary.compressedSize,
      uncompressedSize: rawBytes.length,
      entryName: summary.name,
    );

    if (policy.strictChecksum && !summary.isDirectory) {
      final actualCrc = Crc32.compute(rawBytes);
      if (actualCrc != summary.crc32) {
        throw ArchiveChecksumException(
          'ZIP entry CRC-32 checksum mismatch.',
          expected: summary.crc32,
          actual: actualCrc,
          entryName: summary.name,
          offset: summary.localHeaderOffset,
        );
      }
    }

    if (summary.type == ArchiveEntryType.symbolicLink) {
      final target = utf8.decode(rawBytes, allowMalformed: true);
      return ArchiveEntry(
        name: summary.name,
        type: ArchiveEntryType.symbolicLink,
        linkTarget: target,
        compressedSize: summary.compressedSize,
        crc32: summary.crc32,
        modifiedTime: summary.modifiedTime,
        permissions: summary.permissions,
        comment: summary.comment,
        compressionMethod: summary.compressionMethod,
        isEncrypted: summary.isEncrypted,
      );
    }

    return ArchiveEntry(
      name: summary.name,
      bytes: summary.isDirectory ? Uint8List(0) : rawBytes,
      type: summary.type,
      compressedSize: summary.compressedSize,
      crc32: summary.crc32,
      modifiedTime: summary.modifiedTime,
      permissions: summary.permissions,
      comment: summary.comment,
      compressionMethod: summary.compressionMethod,
      isEncrypted: summary.isEncrypted,
    );
  }

  static _ParsedCentralDirectory _parseCentralDirectory(
    Uint8List input,
    ArchiveSecurityPolicy policy,
  ) {
    if (input.length < 22) {
      throw const ArchiveFormatException(
        'Input is too small to be a valid ZIP archive (minimum 22 bytes).',
        offset: 0,
      );
    }

    final eocdOffset = _findEocdOffset(input);
    if (eocdOffset < 0) {
      throw const ArchiveFormatException(
        'ZIP End of Central Directory (EOCD) signature not found.',
      );
    }

    final eocdReader = ByteReader(input, offset: eocdOffset + 4);
    eocdReader.skip(4); // disk numbers
    var entryCount = eocdReader.readUint16LE();
    final totalEntryCount16 = eocdReader.readUint16LE();
    if (totalEntryCount16 > entryCount) {
      entryCount = totalEntryCount16;
    }
    var cdSize = eocdReader.readUint32LE();
    var cdOffset = eocdReader.readUint32LE();
    final commentLen = eocdReader.readUint16LE();
    final comment = commentLen > 0
        ? utf8.decode(
            eocdReader.readBytesView(commentLen),
            allowMalformed: true,
          )
        : null;

    var isZip64 = false;

    // Check for ZIP64 End of Central Directory Locator right before EOCD.
    if (eocdOffset >= 20) {
      final locReader = ByteReader(input, offset: eocdOffset - 20);
      if (locReader.readUint32LE() == _zip64LocatorSig) {
        locReader.skip(4); // disk with zip64 EOCD
        final zip64EocdOffset = locReader.readUint64LE();
        if (zip64EocdOffset >= 0 && zip64EocdOffset + 56 <= input.length) {
          final z64 = ByteReader(input, offset: zip64EocdOffset);
          if (z64.readUint32LE() == _zip64EocdSig) {
            isZip64 = true;
            z64.skip(8 + 2 + 2 + 4 + 4);
            final z64EntriesOnDisk = z64.readUint64LE();
            final z64TotalEntries = z64.readUint64LE();
            entryCount = z64TotalEntries > z64EntriesOnDisk
                ? z64TotalEntries
                : z64EntriesOnDisk;
            cdSize = z64.readUint64LE();
            cdOffset = z64.readUint64LE();
          }
        }
      }
    }

    policy.checkEntryCount(entryCount);

    if (cdOffset + cdSize > input.length) {
      throw ArchiveFormatException(
        'ZIP Central Directory range [$cdOffset, ${cdOffset + cdSize}) '
        'exceeds buffer length (${input.length}).',
        offset: cdOffset,
      );
    }

    final reader = ByteReader(input, offset: cdOffset, end: cdOffset + cdSize);
    final records = <_ParsedCentralRecord>[];

    for (var i = 0; i < entryCount; i++) {
      if (reader.isEof) {
        throw ArchiveFormatException(
          'Unexpected end of ZIP Central Directory at entry $i of $entryCount.',
          offset: reader.offset,
        );
      }
      final sig = reader.readUint32LE();
      if (sig != _centralHeaderSig) {
        throw ArchiveFormatException(
          'Invalid ZIP Central Directory entry signature at offset '
          '${reader.offset - 4}.',
          offset: reader.offset - 4,
        );
      }

      final versionMadeBy = reader.readUint16LE();
      reader.skip(2); // version needed
      final flags = reader.readUint16LE();
      final methodCode = reader.readUint16LE();
      final dosTime = reader.readUint16LE();
      final dosDate = reader.readUint16LE();
      final crc32 = reader.readUint32LE();
      var compressedSize = reader.readUint32LE();
      var uncompressedSize = reader.readUint32LE();
      final nameLen = reader.readUint16LE();
      final extraLen = reader.readUint16LE();
      final entryCommentLen = reader.readUint16LE();
      reader.skip(4); // diskStart(2) + internalAttr(2)
      final externalAttr = reader.readUint32LE();
      var localHeaderOffset = reader.readUint32LE();

      final nameBytes = reader.readBytesView(nameLen);
      final extraBytes = reader.readBytesView(extraLen);
      final entryCommentBytes = reader.readBytesView(entryCommentLen);

      final isUtf8 = (flags & 0x0800) != 0;
      var rawName = isUtf8
          ? utf8.decode(nameBytes, allowMalformed: true)
          : _decodeZipString(nameBytes);
      final entryComment = entryCommentBytes.isEmpty
          ? null
          : (isUtf8
                ? utf8.decode(entryCommentBytes, allowMalformed: true)
                : _decodeZipString(entryCommentBytes));

      var modifiedTime = _fromDosDateTime(dosDate, dosTime);

      // Parse Extra Fields (ZIP64 0x0001, Extended Timestamp 0x5455,
      // Info-ZIP Unicode Path 0x7075).
      final extraReader = ByteReader(extraBytes);
      while (extraReader.remaining >= 4) {
        final tag = extraReader.readUint16LE();
        final size = extraReader.readUint16LE();
        if (size > extraReader.remaining) {
          break;
        }
        final fieldStart = extraReader.offset;
        final fieldEnd = fieldStart + size;

        if (tag == 0x0001) {
          isZip64 = true;
          if (uncompressedSize == 0xffffffff &&
              extraReader.offset + 8 <= fieldEnd) {
            uncompressedSize = extraReader.readUint64LE();
          }
          if (compressedSize == 0xffffffff &&
              extraReader.offset + 8 <= fieldEnd) {
            compressedSize = extraReader.readUint64LE();
          }
          if (localHeaderOffset == 0xffffffff &&
              extraReader.offset + 8 <= fieldEnd) {
            localHeaderOffset = extraReader.readUint64LE();
          }
        } else if (tag == 0x5455 && size >= 5) {
          final tsFlags = extraReader.readUint8();
          if ((tsFlags & 1) != 0) {
            final unixSec = extraReader.readUint32LE();
            modifiedTime = DateTime.fromMillisecondsSinceEpoch(
              unixSec * 1000,
              isUtc: true,
            );
          }
        } else if (tag == 0x7075 && size >= 5) {
          final version = extraReader.readUint8();
          final nameCrc = extraReader.readUint32LE();
          if (version == 1 && Crc32.compute(nameBytes) == nameCrc) {
            rawName = utf8.decode(
              extraReader.readBytesView(fieldEnd - extraReader.offset),
              allowMalformed: true,
            );
          }
        }
        extraReader.offset = fieldEnd;
      }

      // Determine entry type & permissions.
      final hostOs = (versionMadeBy >>> 8) & 0xff;
      final unixModeFull = (externalAttr >>> 16) & 0xffff;
      final unixFileType = unixModeFull & 0xf000;

      late final ArchiveEntryType entryType;
      if (hostOs == 3 && unixFileType == 0xa000) {
        entryType = ArchiveEntryType.symbolicLink;
      } else if (rawName.endsWith('/') ||
          (hostOs == 3 && unixFileType == 0x4000) ||
          (hostOs == 0 &&
              (externalAttr & 0x10) != 0 &&
              uncompressedSize == 0)) {
        entryType = ArchiveEntryType.directory;
      } else {
        entryType = ArchiveEntryType.file;
      }

      final permissions = (hostOs == 3 && (unixModeFull & 0x0fff) != 0)
          ? (unixModeFull & 0x0fff)
          : (entryType == ArchiveEntryType.directory ? 0x1ed : 0x1a4);

      final safeName = policy.sanitizePath(
        rawName,
        isDirectory: entryType == ArchiveEntryType.directory,
      );

      records.add(
        _ParsedCentralRecord(
          flags: flags,
          dosTime: dosTime,
          summary: ZipEntrySummary(
            name: safeName,
            type: entryType,
            compressionMethodCode: methodCode,
            compressedSize: compressedSize,
            uncompressedSize: uncompressedSize,
            crc32: crc32,
            modifiedTime: modifiedTime,
            permissions: permissions,
            isEncrypted: (flags & 0x0001) != 0,
            localHeaderOffset: localHeaderOffset,
            comment: entryComment,
          ),
        ),
      );
    }

    return _ParsedCentralDirectory(
      records: records,
      isZip64: isZip64,
      comment: comment,
    );
  }

  static int _findEocdOffset(Uint8List input) {
    final maxBack = input.length < 65557 ? input.length : 65557;
    final minPos = input.length - maxBack;
    for (var pos = input.length - 22; pos >= minPos; pos--) {
      if (input[pos] == 0x50 &&
          input[pos + 1] == 0x4b &&
          input[pos + 2] == 0x05 &&
          input[pos + 3] == 0x06) {
        final commentLen = input[pos + 20] | (input[pos + 21] << 8);
        if (pos + 22 + commentLen == input.length) {
          return pos;
        }
      }
    }
    return -1;
  }

  static String _decodeZipString(Uint8List bytes) {
    try {
      return utf8.decode(bytes);
    } on FormatException {
      return latin1.decode(bytes);
    }
  }

  static DateTime _fromDosDateTime(int dosDate, int dosTime) {
    final year = ((dosDate >>> 9) & 0x7f) + 1980;
    final month = ((dosDate >>> 5) & 0x0f).clamp(1, 12);
    final day = (dosDate & 0x1f).clamp(1, 31);
    final hour = ((dosTime >>> 11) & 0x1f).clamp(0, 23);
    final minute = ((dosTime >>> 5) & 0x3f).clamp(0, 59);
    final second = ((dosTime & 0x1f) * 2).clamp(0, 59);
    return DateTime.utc(year, month, day, hour, minute, second);
  }
}

final class _ParsedCentralRecord {
  const _ParsedCentralRecord({
    required this.flags,
    required this.dosTime,
    required this.summary,
  });

  final int flags;
  final int dosTime;
  final ZipEntrySummary summary;
}

final class _ParsedCentralDirectory {
  const _ParsedCentralDirectory({
    required this.records,
    required this.isZip64,
    this.comment,
  });

  final List<_ParsedCentralRecord> records;
  final bool isZip64;
  final String? comment;
}

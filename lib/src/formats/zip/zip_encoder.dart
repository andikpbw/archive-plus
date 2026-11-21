import 'dart:convert';
import 'dart:typed_data';

import '../../codecs/bzip2_codec.dart';
import '../../codecs/deflate/deflater.dart';
import '../../core/archive.dart';
import '../../core/archive_options.dart';
import '../../core/archive_progress.dart';
import '../../util/byte_buffer.dart';
import '../../util/checksums.dart';
import '../../util/path_sanitizer.dart';
import 'zip_crypto.dart';

/// PKWARE APPNOTE 6.3.x compliant ZIP archive encoder supporting Store,
/// DEFLATE, and BZip2 compression, UTF-8 names, UNIX permissions, Extended
/// Timestamps (`0x5455`), ZipCrypto encryption, and automatic ZIP64 records.
final class ZipEncoder {
  ZipEncoder._();

  static const int _localHeaderSig = 0x04034b50;
  static const int _centralHeaderSig = 0x02014b50;
  static const int _eocdSig = 0x06054b50;
  static const int _zip64EocdSig = 0x06064b50;
  static const int _zip64LocatorSig = 0x07064b50;
  static const int _zip64Threshold32 = 0xffffffff;
  static const int _zip64Threshold16 = 0xffff;

  /// Encodes [archive] into PKWARE ZIP bytes according to [options].
  static Uint8List encode(
    Archive archive, {
    ZipEncodeOptions options = const ZipEncodeOptions(),
  }) {
    final cancel = options.cancelToken;
    cancel?.throwIfCancelled();

    final entriesToEncode = options.filter == null
        ? archive.entries
        : archive.entries
              .where(
                (e) => options.filter!.matches(
                  e.name,
                  size: e.size,
                  isDirectory: e.isDirectory,
                ),
              )
              .toList();

    final totalEntries = entriesToEncode.length;
    final totalRawBytes = entriesToEncode.fold<int>(
      0,
      (sum, e) => sum + e.size,
    );

    final out = ByteWriter(totalRawBytes ~/ 2 + 256);
    final centralRecords = <_CentralRecord>[];
    var processedBytes = 0;
    var compressedTotal = 0;
    var needsZip64Archive =
        options.forceZip64 || totalEntries >= _zip64Threshold16;

    for (var i = 0; i < totalEntries; i++) {
      cancel?.throwIfCancelled();
      final entry = entriesToEncode[i];

      options.onProgress?.call(
        ArchiveProgress(
          phase: ArchivePhase.compressing,
          entryName: entry.name,
          processedEntries: i,
          totalEntries: totalEntries,
          bytesProcessed: processedBytes,
          totalBytes: totalRawBytes,
          compressedBytes: compressedTotal,
        ),
      );

      final sanitizedName = PathSanitizer.sanitize(
        entry.name,
        allowPathTraversal: true,
        isDirectory: entry.isDirectory,
      );
      final nameBytes = utf8.encode(sanitizedName);
      final commentText = entry.comment;
      final commentBytes = commentText == null
          ? Uint8List(0)
          : utf8.encode(commentText);

      final Uint8List rawPayload;
      if (entry.isDirectory) {
        rawPayload = Uint8List(0);
      } else if (entry.isSymbolicLink && entry.linkTarget != null) {
        rawPayload = utf8.encode(entry.linkTarget!);
      } else {
        rawPayload = entry.bytes;
      }

      final crc = Crc32.compute(rawPayload);
      var method = entry.isDirectory || entry.isSymbolicLink
          ? CompressionMethod.store
          : (entry.compressionMethod ?? options.method);

      if (options.level == CompressionLevel.none) {
        method = CompressionMethod.store;
      }

      Uint8List encodedPayload;
      switch (method) {
        case CompressionMethod.store:
          encodedPayload = rawPayload;
        case CompressionMethod.deflate:
          final deflated = DeflateDeflater.deflate(
            rawPayload,
            level: options.level.level,
          );
          if (options.autoStoreIfLarger &&
              deflated.length >= rawPayload.length) {
            method = CompressionMethod.store;
            encodedPayload = rawPayload;
          } else {
            encodedPayload = deflated;
          }
        case CompressionMethod.bzip2:
          final bz2 = BZip2PlusCodec.encodeBytes(
            rawPayload,
            options: BZip2Options(
              blockSize100k: options.level.level.clamp(1, 9),
            ),
          );
          if (options.autoStoreIfLarger && bz2.length >= rawPayload.length) {
            method = CompressionMethod.store;
            encodedPayload = rawPayload;
          } else {
            encodedPayload = bz2;
          }
      }

      var flags = 0;
      if (options.useUtf8) {
        flags |= 0x0800; // General Purpose Bit 11 (UTF-8 EFS)
      }

      final password = options.password;
      final encryptEntry =
          password != null && password.isNotEmpty && !entry.isDirectory;
      if (encryptEntry) {
        flags |= 0x0001; // Encrypted bit
        encodedPayload = ZipCrypto.encrypt(
          encodedPayload,
          password: password,
          checkByte: (crc >>> 24) & 0xff,
        );
      }

      final localOffset = out.length;
      final uncompressedSize = rawPayload.length;
      final compressedSize = encodedPayload.length;
      final entryNeedsZip64 =
          options.forceZip64 ||
          uncompressedSize >= _zip64Threshold32 ||
          compressedSize >= _zip64Threshold32 ||
          localOffset >= _zip64Threshold32;
      if (entryNeedsZip64) {
        needsZip64Archive = true;
      }

      final dosDt = _toDosDateTime(entry.modifiedTime);

      // Build Local File Header extra field.
      final localExtra = ByteWriter(32);
      if (entryNeedsZip64) {
        localExtra
          ..writeUint16LE(0x0001) // ZIP64 tag
          ..writeUint16LE(16)
          ..writeUint64LE(uncompressedSize)
          ..writeUint64LE(compressedSize);
      }
      if (options.includeExtendedTimestamp) {
        final unixSec =
            (entry.modifiedTime.toUtc().millisecondsSinceEpoch ~/ 1000) &
            0xffffffff;
        localExtra
          ..writeUint16LE(0x5455) // Extended Timestamp (UT)
          ..writeUint16LE(5)
          ..writeUint8(1) // mtime present
          ..writeUint32LE(unixSec);
      }
      final localExtraBytes = localExtra.toBytesView();

      final versionNeeded = entryNeedsZip64
          ? 45
          : (method == CompressionMethod.bzip2 ? 46 : 20);

      // Local File Header.
      out
        ..writeUint32LE(_localHeaderSig)
        ..writeUint16LE(versionNeeded)
        ..writeUint16LE(flags)
        ..writeUint16LE(method.zipCode)
        ..writeUint16LE(dosDt.time)
        ..writeUint16LE(dosDt.date)
        ..writeUint32LE(crc)
        ..writeUint32LE(entryNeedsZip64 ? _zip64Threshold32 : compressedSize)
        ..writeUint32LE(entryNeedsZip64 ? _zip64Threshold32 : uncompressedSize)
        ..writeUint16LE(nameBytes.length)
        ..writeUint16LE(localExtraBytes.length)
        ..writeBytes(nameBytes)
        ..writeBytes(localExtraBytes)
        ..writeBytes(encodedPayload);

      final unixMode = _unixExternalAttributes(entry);
      centralRecords.add(
        _CentralRecord(
          nameBytes: nameBytes,
          commentBytes: commentBytes,
          versionNeeded: versionNeeded,
          flags: flags,
          methodCode: method.zipCode,
          dosTime: dosDt.time,
          dosDate: dosDt.date,
          crc32: crc,
          compressedSize: compressedSize,
          uncompressedSize: uncompressedSize,
          localHeaderOffset: localOffset,
          externalAttributes: unixMode,
          modifiedTime: entry.modifiedTime,
          needsZip64: entryNeedsZip64,
        ),
      );

      processedBytes += rawPayload.length;
      compressedTotal += compressedSize;
    }

    // Central Directory.
    final centralDirOffset = out.length;
    for (final rec in centralRecords) {
      final centralExtra = ByteWriter(36);
      if (rec.needsZip64) {
        centralExtra
          ..writeUint16LE(0x0001)
          ..writeUint16LE(24)
          ..writeUint64LE(rec.uncompressedSize)
          ..writeUint64LE(rec.compressedSize)
          ..writeUint64LE(rec.localHeaderOffset);
      }
      if (options.includeExtendedTimestamp) {
        final unixSec =
            (rec.modifiedTime.toUtc().millisecondsSinceEpoch ~/ 1000) &
            0xffffffff;
        centralExtra
          ..writeUint16LE(0x5455)
          ..writeUint16LE(5)
          ..writeUint8(1)
          ..writeUint32LE(unixSec);
      }
      final centralExtraBytes = centralExtra.toBytesView();
      final versionMadeBy = (3 << 8) | rec.versionNeeded; // 3 = UNIX

      out
        ..writeUint32LE(_centralHeaderSig)
        ..writeUint16LE(versionMadeBy)
        ..writeUint16LE(rec.versionNeeded)
        ..writeUint16LE(rec.flags)
        ..writeUint16LE(rec.methodCode)
        ..writeUint16LE(rec.dosTime)
        ..writeUint16LE(rec.dosDate)
        ..writeUint32LE(rec.crc32)
        ..writeUint32LE(rec.needsZip64 ? _zip64Threshold32 : rec.compressedSize)
        ..writeUint32LE(
          rec.needsZip64 ? _zip64Threshold32 : rec.uncompressedSize,
        )
        ..writeUint16LE(rec.nameBytes.length)
        ..writeUint16LE(centralExtraBytes.length)
        ..writeUint16LE(rec.commentBytes.length)
        ..writeUint16LE(0) // disk number start
        ..writeUint16LE(0) // internal file attributes
        ..writeUint32LE(rec.externalAttributes)
        ..writeUint32LE(
          rec.needsZip64 ? _zip64Threshold32 : rec.localHeaderOffset,
        )
        ..writeBytes(rec.nameBytes)
        ..writeBytes(centralExtraBytes)
        ..writeBytes(rec.commentBytes);
    }

    final centralDirSize = out.length - centralDirOffset;
    if (centralDirOffset >= _zip64Threshold32 ||
        centralDirSize >= _zip64Threshold32) {
      needsZip64Archive = true;
    }

    if (needsZip64Archive) {
      final zip64EocdOffset = out.length;
      out
        ..writeUint32LE(_zip64EocdSig)
        ..writeUint64LE(44) // size of remaining ZIP64 EOCD record
        ..writeUint16LE((3 << 8) | 45) // version made by
        ..writeUint16LE(45) // version needed
        ..writeUint32LE(0) // this disk
        ..writeUint32LE(0) // disk with start of CD
        ..writeUint64LE(centralRecords.length)
        ..writeUint64LE(centralRecords.length)
        ..writeUint64LE(centralDirSize)
        ..writeUint64LE(centralDirOffset)
        // ZIP64 EOCD Locator.
        ..writeUint32LE(_zip64LocatorSig)
        ..writeUint32LE(0)
        ..writeUint64LE(zip64EocdOffset)
        ..writeUint32LE(1);
    }

    final archiveComment = options.comment ?? archive.comment;
    final archiveCommentBytes = archiveComment == null
        ? Uint8List(0)
        : utf8.encode(archiveComment);

    // End of Central Directory (EOCD).
    out
      ..writeUint32LE(_eocdSig)
      ..writeUint16LE(0) // disk number
      ..writeUint16LE(0) // start disk
      ..writeUint16LE(
        centralRecords.length >= _zip64Threshold16
            ? _zip64Threshold16
            : centralRecords.length,
      )
      ..writeUint16LE(
        centralRecords.length >= _zip64Threshold16
            ? _zip64Threshold16
            : centralRecords.length,
      )
      ..writeUint32LE(
        centralDirSize >= _zip64Threshold32
            ? _zip64Threshold32
            : centralDirSize,
      )
      ..writeUint32LE(
        centralDirOffset >= _zip64Threshold32
            ? _zip64Threshold32
            : centralDirOffset,
      )
      ..writeUint16LE(archiveCommentBytes.length)
      ..writeBytes(archiveCommentBytes);

    options.onProgress?.call(
      ArchiveProgress(
        phase: ArchivePhase.completed,
        processedEntries: totalEntries,
        totalEntries: totalEntries,
        bytesProcessed: processedBytes,
        totalBytes: totalRawBytes,
        compressedBytes: compressedTotal,
      ),
    );

    return out.toBytes();
  }

  static int _unixExternalAttributes(ArchiveEntry entry) {
    final perm = entry.permissions & 0x0fff;
    final fileTypeBits = switch (entry.type) {
      ArchiveEntryType.directory => 0x4000, // S_IFDIR (0040000)
      ArchiveEntryType.symbolicLink => 0xa000, // S_IFLNK (0120000)
      ArchiveEntryType.file || ArchiveEntryType.hardLink => 0x8000, // S_IFREG
    };
    final dosAttr = entry.isDirectory ? 0x10 : 0x00;
    return (((fileTypeBits | perm) << 16) | dosAttr) & 0xffffffff;
  }

  static ({int time, int date}) _toDosDateTime(DateTime dt) {
    final utc = dt.toUtc();
    final year = utc.year < 1980 ? 1980 : (utc.year > 2107 ? 2107 : utc.year);
    final dosDate = ((year - 1980) << 9) | (utc.month << 5) | utc.day;
    final dosTime = (utc.hour << 11) | (utc.minute << 5) | (utc.second >> 1);
    return (time: dosTime & 0xffff, date: dosDate & 0xffff);
  }
}

final class _CentralRecord {
  const _CentralRecord({
    required this.nameBytes,
    required this.commentBytes,
    required this.versionNeeded,
    required this.flags,
    required this.methodCode,
    required this.dosTime,
    required this.dosDate,
    required this.crc32,
    required this.compressedSize,
    required this.uncompressedSize,
    required this.localHeaderOffset,
    required this.externalAttributes,
    required this.modifiedTime,
    required this.needsZip64,
  });

  final Uint8List nameBytes;
  final Uint8List commentBytes;
  final int versionNeeded;
  final int flags;
  final int methodCode;
  final int dosTime;
  final int dosDate;
  final int crc32;
  final int compressedSize;
  final int uncompressedSize;
  final int localHeaderOffset;
  final int externalAttributes;
  final DateTime modifiedTime;
  final bool needsZip64;
}

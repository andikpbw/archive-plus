import 'dart:convert';
import 'dart:typed_data';

import '../../core/archive.dart';
import '../../core/archive_exceptions.dart';
import '../../core/archive_options.dart';
import '../../core/archive_progress.dart';
import '../../util/byte_buffer.dart';

/// POSIX USTAR, PAX Extended Header (`x`/`g`), GNU LongName (`L`/`K`), and
/// legacy V7 TAR archive decoder with built-in security enforcement.
final class TarDecoder {
  TarDecoder._();

  static const int _blockSize = 512;

  /// Decodes TAR [bytes] into an [Archive] according to [options].
  static Archive decode(
    List<int> bytes, {
    TarDecodeOptions options = const TarDecodeOptions(),
  }) {
    final cancel = options.cancelToken;
    cancel?.throwIfCancelled();

    final input = asUint8List(bytes);
    final policy = options.securityPolicy;
    final archive = Archive();

    final globalPax = <String, String>{};
    var nextPax = <String, String>{};
    String? gnuLongName;
    String? gnuLongLink;

    var offset = 0;
    var entryCount = 0;
    var totalDecodedBytes = 0;

    while (offset + _blockSize <= input.length) {
      cancel?.throwIfCancelled();

      final header = Uint8List.sublistView(input, offset, offset + _blockSize);
      offset += _blockSize;

      if (_isZeroBlock(header)) {
        // Standard TAR EOF marker (one or two consecutive zero blocks).
        break;
      }

      if (policy.strictChecksum) {
        _verifyChecksum(header, offset - _blockSize);
      }

      final rawName = _readNullTerminatedString(header, 0, 100);
      final mode = _parseNumericField(header, 100, 8);
      var size = _parseNumericField(header, 124, 12);
      final mtimeSec = _parseNumericField(header, 136, 12);
      final typeFlag = header[156];
      var linkName = _readNullTerminatedString(header, 157, 100);
      final magic = _readNullTerminatedString(header, 257, 6);
      final prefix = magic == 'ustar'
          ? _readNullTerminatedString(header, 345, 155)
          : '';

      // Apply PAX size override before reading payload.
      final paxSizeStr = nextPax['size'] ?? globalPax['size'];
      if (paxSizeStr != null) {
        final parsed = int.tryParse(paxSizeStr);
        if (parsed != null && parsed >= 0) {
          size = parsed;
        }
      }

      if (size < 0 || offset + size > input.length) {
        throw ArchiveFormatException(
          'TAR entry "$rawName" declares $size bytes exceeding input length.',
          entryName: rawName,
          offset: offset - _blockSize,
        );
      }

      final payload = Uint8List.sublistView(input, offset, offset + size);
      final paddedSize = ((size + _blockSize - 1) ~/ _blockSize) * _blockSize;
      offset += paddedSize;

      // Handle PAX and GNU extension records.
      if (typeFlag == 0x78) {
        // 'x': per-entry PAX extended header
        nextPax.addAll(_parsePaxRecords(payload));
        continue;
      }
      if (typeFlag == 0x67) {
        // 'g': global PAX extended header
        globalPax.addAll(_parsePaxRecords(payload));
        continue;
      }
      if (typeFlag == 0x4c) {
        // 'L': GNU long filename
        gnuLongName = _stripTrailingNulls(
          utf8.decode(payload, allowMalformed: true),
        );
        continue;
      }
      if (typeFlag == 0x4b) {
        // 'K': GNU long link target
        gnuLongLink = _stripTrailingNulls(
          utf8.decode(payload, allowMalformed: true),
        );
        continue;
      }

      // Assemble effective path, link target, mtime, and metadata.
      final mergedPax = <String, String>{...globalPax, ...nextPax};
      nextPax = <String, String>{};

      var fullName =
          gnuLongName ??
          mergedPax['path'] ??
          (prefix.isNotEmpty ? '$prefix/$rawName' : rawName);
      gnuLongName = null;

      if (gnuLongLink != null) {
        linkName = gnuLongLink;
        gnuLongLink = null;
      } else if (mergedPax.containsKey('linkpath')) {
        linkName = mergedPax['linkpath']!;
      }

      DateTime modifiedTime;
      final paxMtime = mergedPax['mtime'];
      if (paxMtime != null) {
        final secDouble = double.tryParse(paxMtime);
        modifiedTime = secDouble != null
            ? DateTime.fromMillisecondsSinceEpoch(
                (secDouble * 1000).round(),
                isUtc: true,
              )
            : DateTime.fromMillisecondsSinceEpoch(mtimeSec * 1000, isUtc: true);
      } else {
        modifiedTime = DateTime.fromMillisecondsSinceEpoch(
          mtimeSec * 1000,
          isUtc: true,
        );
      }

      final ArchiveEntryType entryType;
      switch (typeFlag) {
        case 0x35: // '5' directory
          entryType = ArchiveEntryType.directory;
        case 0x32: // '2' symlink
          entryType = ArchiveEntryType.symbolicLink;
        case 0x31: // '1' hard link
          entryType = ArchiveEntryType.hardLink;
        case 0x30: // '0' regular file
        case 0x00: // legacy NUL regular file
          entryType = fullName.endsWith('/')
              ? ArchiveEntryType.directory
              : ArchiveEntryType.file;
        default:
          // Ignore non-file metadata headers (e.g. FIFO/char/block/volume).
          continue;
      }

      entryCount++;
      policy.checkEntryCount(entryCount, entryName: fullName);

      fullName = policy.sanitizePath(
        fullName,
        isDirectory: entryType == ArchiveEntryType.directory,
      );

      if (options.filter != null &&
          !options.filter!.matches(
            fullName,
            size: size,
            isDirectory: entryType == ArchiveEntryType.directory,
          )) {
        continue;
      }

      policy.checkEntrySize(size, entryName: fullName);
      totalDecodedBytes += entryType == ArchiveEntryType.file ? size : 0;
      policy.checkTotalSize(totalDecodedBytes, entryName: fullName);

      // Remove standard structural PAX keys from custom metadata map.
      final customMeta = <String, String>{...mergedPax}
        ..remove('path')
        ..remove('linkpath')
        ..remove('size')
        ..remove('mtime');

      archive.add(
        ArchiveEntry(
          name: fullName,
          bytes: entryType == ArchiveEntryType.file
              ? Uint8List.fromList(payload)
              : Uint8List(0),
          type: entryType,
          compressedSize: size,
          modifiedTime: modifiedTime,
          permissions: mode & 0xfff,
          linkTarget:
              (entryType == ArchiveEntryType.symbolicLink ||
                  entryType == ArchiveEntryType.hardLink)
              ? linkName
              : null,
          metadata: customMeta.isEmpty ? null : customMeta,
        ),
      );

      options.onProgress?.call(
        ArchiveProgress(
          phase: ArchivePhase.reading,
          entryName: fullName,
          processedEntries: archive.length,
          totalEntries: archive.length,
          bytesProcessed: totalDecodedBytes,
          totalBytes: input.length,
          compressedBytes: offset,
        ),
      );
    }

    options.onProgress?.call(
      ArchiveProgress(
        phase: ArchivePhase.completed,
        processedEntries: archive.length,
        totalEntries: archive.length,
        bytesProcessed: totalDecodedBytes,
        totalBytes: totalDecodedBytes,
        compressedBytes: offset,
      ),
    );

    return archive;
  }

  static bool _isZeroBlock(Uint8List block) {
    for (var i = 0; i < block.length; i++) {
      if (block[i] != 0) {
        return false;
      }
    }
    return true;
  }

  static void _verifyChecksum(Uint8List header, int blockOffset) {
    final recorded = _parseNumericField(header, 148, 8);
    var unsignedSum = 0;
    var signedSum = 0;
    for (var i = 0; i < _blockSize; i++) {
      final b = (i >= 148 && i < 156) ? 0x20 : header[i];
      unsignedSum += b;
      signedSum += b >= 128 ? (b - 256) : b;
    }
    if (recorded != unsignedSum && recorded != signedSum) {
      throw ArchiveChecksumException(
        'TAR header checksum mismatch.',
        expected: recorded,
        actual: unsignedSum,
        offset: blockOffset,
      );
    }
  }

  static String _readNullTerminatedString(
    Uint8List header,
    int offset,
    int length,
  ) {
    var end = offset;
    final limit = offset + length;
    while (end < limit && header[end] != 0) {
      end++;
    }
    final slice = Uint8List.sublistView(header, offset, end);
    return utf8.decode(slice, allowMalformed: true);
  }

  static int _parseNumericField(Uint8List header, int offset, int length) {
    // Support GNU base-256 binary encoding (high bit 0x80 set on first byte).
    if ((header[offset] & 0x80) != 0) {
      var val = header[offset] & 0x7f;
      for (var i = 1; i < length; i++) {
        val = val * 256 + header[offset + i];
      }
      return val;
    }

    var value = 0;
    var started = false;
    for (var i = offset; i < offset + length; i++) {
      final b = header[i];
      if (b == 0 || b == 0x20) {
        if (started) {
          break;
        }
        continue;
      }
      if (b >= 0x30 && b <= 0x37) {
        started = true;
        value = (value << 3) | (b - 0x30);
      } else {
        throw ArchiveFormatException(
          'Invalid octal digit 0x${b.toRadixString(16)} in TAR header.',
          offset: i,
        );
      }
    }
    return value;
  }

  static Map<String, String> _parsePaxRecords(Uint8List payload) {
    final result = <String, String>{};
    var pos = 0;
    final n = payload.length;

    while (pos < n) {
      final spaceIdx = payload.indexOf(0x20, pos);
      if (spaceIdx == -1) {
        break;
      }
      final lenStr = ascii.decode(
        Uint8List.sublistView(payload, pos, spaceIdx),
      );
      final recordLen = int.tryParse(lenStr);
      if (recordLen == null || recordLen <= 0 || pos + recordLen > n) {
        break;
      }
      final recEnd = pos + recordLen;
      final kvEnd = (recEnd > spaceIdx + 1 && payload[recEnd - 1] == 0x0a)
          ? recEnd - 1
          : recEnd;
      final kvStr = utf8.decode(
        Uint8List.sublistView(payload, spaceIdx + 1, kvEnd),
        allowMalformed: true,
      );
      final eqIdx = kvStr.indexOf('=');
      if (eqIdx > 0) {
        result[kvStr.substring(0, eqIdx)] = kvStr.substring(eqIdx + 1);
      }
      pos = recEnd;
    }
    return result;
  }

  static String _stripTrailingNulls(String value) {
    var end = value.length;
    while (end > 0 && value.codeUnitAt(end - 1) == 0) {
      end--;
    }
    return value.substring(0, end);
  }
}

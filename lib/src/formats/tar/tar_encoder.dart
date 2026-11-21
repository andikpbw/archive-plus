import 'dart:convert';
import 'dart:typed_data';

import '../../core/archive.dart';
import '../../core/archive_options.dart';
import '../../core/archive_progress.dart';
import '../../util/byte_buffer.dart';
import '../../util/path_sanitizer.dart';

/// POSIX USTAR + PAX Extended Header TAR archive encoder.
final class TarEncoder {
  TarEncoder._();

  static const int _blockSize = 512;
  static const int _maxOctalSize = 0x1ffffffff; // 8 GiB - 1

  /// Encodes [archive] into POSIX USTAR/PAX TAR bytes.
  static Uint8List encode(
    Archive archive, {
    TarEncodeOptions options = const TarEncodeOptions(),
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
    final totalBytes = entriesToEncode.fold<int>(0, (s, e) => s + e.size);
    final out = ByteWriter(totalBytes + totalEntries * 1024 + 1024);
    var processedBytes = 0;

    for (var i = 0; i < totalEntries; i++) {
      cancel?.throwIfCancelled();
      final entry = entriesToEncode[i];

      options.onProgress?.call(
        ArchiveProgress(
          phase: ArchivePhase.writing,
          entryName: entry.name,
          processedEntries: i,
          totalEntries: totalEntries,
          bytesProcessed: processedBytes,
          totalBytes: totalBytes,
          compressedBytes: out.length,
        ),
      );

      final path = PathSanitizer.sanitize(
        entry.name,
        allowPathTraversal: true,
        isDirectory: entry.isDirectory,
      );
      final linkTarget = entry.linkTarget ?? '';
      final payload = entry.isFile ? entry.bytes : Uint8List(0);
      final pathBytes = utf8.encode(path);
      final linkBytes = utf8.encode(linkTarget);

      // Check whether a PAX Extended Header is needed.
      final paxRecords = <String, String>{...entry.metadata};
      final split = _trySplitUstarPath(pathBytes);
      if (split == null || !_isPureAscii(pathBytes)) {
        paxRecords['path'] = path;
      }
      if (linkBytes.length > 100 ||
          (linkBytes.isNotEmpty && !_isPureAscii(linkBytes))) {
        paxRecords['linkpath'] = linkTarget;
      }
      if (payload.length > _maxOctalSize) {
        paxRecords['size'] = '${payload.length}';
      }

      if (options.usePaxHeaders && paxRecords.isNotEmpty) {
        final paxPayload = _buildPaxPayload(paxRecords);
        final paxName = 'PaxHeaders.0/${_truncateAscii(path, 80)}';
        _writeHeaderBlock(
          out: out,
          name: paxName,
          prefix: '',
          mode: 0x1a4,
          size: paxPayload.length,
          mtimeSeconds:
              entry.modifiedTime.toUtc().millisecondsSinceEpoch ~/ 1000,
          typeFlag: 0x78, // 'x'
          linkName: '',
        );
        out.writeBytes(paxPayload);
        final pad =
            (_blockSize - (paxPayload.length % _blockSize)) % _blockSize;
        out.writeZeros(pad);
      }

      final ustarName = split?.name ?? _truncateAscii(path, 100);
      final ustarPrefix = split?.prefix ?? '';
      final typeFlag = switch (entry.type) {
        ArchiveEntryType.file => 0x30, // '0'
        ArchiveEntryType.directory => 0x35, // '5'
        ArchiveEntryType.symbolicLink => 0x32, // '2'
        ArchiveEntryType.hardLink => 0x31, // '1'
      };
      final mode = entry.permissions != 0
          ? entry.permissions
          : (entry.isDirectory
                ? options.defaultDirectoryPermissions
                : options.defaultFilePermissions);

      _writeHeaderBlock(
        out: out,
        name: ustarName,
        prefix: ustarPrefix,
        mode: mode,
        size: payload.length > _maxOctalSize ? 0 : payload.length,
        mtimeSeconds: entry.modifiedTime.toUtc().millisecondsSinceEpoch ~/ 1000,
        typeFlag: typeFlag,
        linkName: _truncateAscii(linkTarget, 100),
      );

      if (payload.isNotEmpty) {
        out.writeBytes(payload);
        final pad = (_blockSize - (payload.length % _blockSize)) % _blockSize;
        out.writeZeros(pad);
      }

      processedBytes += payload.length;
    }

    // Two 512-byte zero blocks mark end-of-archive.
    out.writeZeros(_blockSize * 2);

    options.onProgress?.call(
      ArchiveProgress(
        phase: ArchivePhase.completed,
        processedEntries: totalEntries,
        totalEntries: totalEntries,
        bytesProcessed: processedBytes,
        totalBytes: totalBytes,
        compressedBytes: out.length,
      ),
    );

    return out.toBytes();
  }

  static void _writeHeaderBlock({
    required ByteWriter out,
    required String name,
    required String prefix,
    required int mode,
    required int size,
    required int mtimeSeconds,
    required int typeFlag,
    required String linkName,
  }) {
    final header = Uint8List(_blockSize);

    _writeFixedString(header, 0, 100, name);
    _writeOctal(header, 100, 8, mode & 0xfff);
    _writeOctal(header, 108, 8, 0); // uid
    _writeOctal(header, 116, 8, 0); // gid
    _writeOctal(header, 124, 12, size < 0 ? 0 : size);
    _writeOctal(header, 136, 12, mtimeSeconds < 0 ? 0 : mtimeSeconds);

    // Fill checksum field with ASCII spaces prior to computing sum.
    header.fillRange(148, 156, 0x20);
    header[156] = typeFlag;
    _writeFixedString(header, 157, 100, linkName);

    // POSIX USTAR magic "ustar\0" and version "00".
    _writeFixedString(header, 257, 6, 'ustar');
    header[263] = 0x30; // '0'
    header[264] = 0x30; // '0'

    _writeFixedString(header, 345, 155, prefix);

    var sum = 0;
    for (var i = 0; i < _blockSize; i++) {
      sum += header[i];
    }
    // Standard 6-digit octal checksum + NUL + space.
    final oct = sum.toRadixString(8).padLeft(6, '0');
    for (var i = 0; i < 6; i++) {
      header[148 + i] = oct.codeUnitAt(i);
    }
    header[154] = 0;
    header[155] = 0x20;

    out.writeBytes(header);
  }

  static Uint8List _buildPaxPayload(Map<String, String> records) {
    final writer = ByteWriter();
    for (final entry in records.entries) {
      final body = ' ${entry.key}=${entry.value}\n';
      final bodyBytes = utf8.encode(body);
      var totalLen = bodyBytes.length + 1;
      while (true) {
        final lenStr = '$totalLen';
        final computed = lenStr.length + bodyBytes.length;
        if (computed == totalLen) {
          writer
            ..writeBytes(ascii.encode(lenStr))
            ..writeBytes(bodyBytes);
          break;
        }
        totalLen = computed;
      }
    }
    return writer.toBytes();
  }

  static ({String prefix, String name})? _trySplitUstarPath(
    List<int> pathBytes,
  ) {
    if (pathBytes.length <= 100) {
      return (prefix: '', name: utf8.decode(pathBytes));
    }
    if (pathBytes.length > 255) {
      return null;
    }
    // Split on the last '/' where prefix <= 155 and name <= 100.
    for (var i = pathBytes.length - 1; i > 0; i--) {
      if (pathBytes[i] == 0x2f) {
        final prefixLen = i;
        final nameLen = pathBytes.length - i - 1;
        if (prefixLen <= 155 && nameLen > 0 && nameLen <= 100) {
          return (
            prefix: utf8.decode(pathBytes.sublist(0, i)),
            name: utf8.decode(pathBytes.sublist(i + 1)),
          );
        }
      }
    }
    return null;
  }

  static bool _isPureAscii(List<int> bytes) {
    for (final b in bytes) {
      if (b > 0x7f) {
        return false;
      }
    }
    return true;
  }

  static String _truncateAscii(String input, int maxBytes) {
    final encoded = utf8.encode(input);
    if (encoded.length <= maxBytes) {
      return input;
    }
    final safe = <int>[];
    for (var i = 0; i < encoded.length && safe.length < maxBytes; i++) {
      final b = encoded[i];
      safe.add(
        b < 0x80 ? b : 0x5f,
      ); // replace non-ASCII with '_' in USTAR fallback
    }
    return ascii.decode(safe);
  }

  static void _writeFixedString(
    Uint8List target,
    int offset,
    int maxLen,
    String value,
  ) {
    final bytes = utf8.encode(value);
    final len = bytes.length < maxLen ? bytes.length : maxLen;
    target.setRange(offset, offset + len, bytes);
  }

  static void _writeOctal(Uint8List target, int offset, int width, int value) {
    final digits = width - 1;
    final oct = value.toRadixString(8);
    final padded = oct.length > digits
        ? oct.substring(oct.length - digits)
        : oct.padLeft(digits, '0');
    for (var i = 0; i < digits; i++) {
      target[offset + i] = padded.codeUnitAt(i);
    }
    target[offset + digits] = 0;
  }
}

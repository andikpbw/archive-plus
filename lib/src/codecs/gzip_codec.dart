import 'dart:convert';
import 'dart:typed_data';

import '../core/archive_exceptions.dart';
import '../core/archive_options.dart';
import '../util/byte_buffer.dart';
import '../util/checksums.dart';
import 'deflate/deflater.dart';
import 'deflate/inflater.dart';

/// Metadata parsed from an RFC 1952 GZIP member header.
final class GZipMetadata {
  /// Creates a [GZipMetadata] instance.
  const GZipMetadata({
    this.filename,
    this.comment,
    this.modifiedTime,
    this.extra,
    this.os = 255,
  });

  /// Original filename (`FNAME`), if present.
  final String? filename;

  /// Comment string (`FCOMMENT`), if present.
  final String? comment;

  /// Modification timestamp (`MTIME`), or `null` when zero in header.
  final DateTime? modifiedTime;

  /// Raw extra header bytes (`FEXTRA`), if present.
  final Uint8List? extra;

  /// Operating system byte from the GZIP header (`255` = unknown).
  final int os;
}

/// Decoded GZIP payload together with its parsed [metadata].
final class GZipDecodedResult {
  /// Creates a [GZipDecodedResult].
  const GZipDecodedResult({required this.bytes, required this.metadata});

  /// Decompressed payload bytes (concatenated across all GZIP members).
  final Uint8List bytes;

  /// Header metadata from the first GZIP member.
  final GZipMetadata metadata;
}

/// Pure Dart RFC 1952 GZIP [Codec] supporting optional header metadata
/// (`FNAME`, `FCOMMENT`, `FEXTRA`, `FHCRC`), multi-member concatenated streams,
/// and streaming via `dart:convert`.
final class GZipPlusCodec extends Codec<List<int>, List<int>> {
  /// Creates a [GZipPlusCodec] with the given [options].
  const GZipPlusCodec({this.options = const GZipOptions()});

  /// Encoding and decoding configuration.
  final GZipOptions options;

  static const int _fhcrc = 0x02;
  static const int _fextra = 0x04;
  static const int _fname = 0x08;
  static const int _fcomment = 0x10;

  @override
  Converter<List<int>, List<int>> get encoder => _GZipEncoder(options);

  @override
  Converter<List<int>, List<int>> get decoder => _GZipDecoder(options);

  /// Compresses [bytes] into an RFC 1952 GZIP byte stream.
  static Uint8List encodeBytes(
    List<int> bytes, {
    GZipOptions options = const GZipOptions(),
  }) {
    final raw = asUint8List(bytes);
    final compressed = DeflateDeflater.deflate(raw, level: options.level.level);
    final crc = Crc32.compute(raw);

    var flg = 0;
    if (options.includeHeaderCrc) {
      flg |= _fhcrc;
    }
    if (options.extra != null && options.extra!.isNotEmpty) {
      flg |= _fextra;
    }
    if (options.filename != null) {
      flg |= _fname;
    }
    if (options.comment != null) {
      flg |= _fcomment;
    }

    final mtime = options.modifiedTime != null
        ? (options.modifiedTime!.toUtc().millisecondsSinceEpoch ~/ 1000) &
              0xffffffff
        : 0;
    final xfl = switch (options.level) {
      CompressionLevel.best || CompressionLevel.high => 2,
      CompressionLevel.fastest || CompressionLevel.none => 4,
      _ => 0,
    };

    final header = ByteWriter(32)
      ..writeUint8(0x1f)
      ..writeUint8(0x8b)
      ..writeUint8(0x08) // DEFLATE
      ..writeUint8(flg)
      ..writeUint32LE(mtime)
      ..writeUint8(xfl)
      ..writeUint8(0xff); // OS: unknown

    if ((flg & _fextra) != 0) {
      final extra = options.extra!;
      header
        ..writeUint16LE(extra.length)
        ..writeBytes(extra);
    }
    if ((flg & _fname) != 0) {
      header
        ..writeBytes(latin1.encode(options.filename!.replaceAll('\u0000', '')))
        ..writeUint8(0);
    }
    if ((flg & _fcomment) != 0) {
      header
        ..writeBytes(latin1.encode(options.comment!.replaceAll('\u0000', '')))
        ..writeUint8(0);
    }

    final headerBytes = header.toBytesView();
    final out = ByteWriter(headerBytes.length + compressed.length + 12)
      ..writeBytes(headerBytes);
    if (options.includeHeaderCrc) {
      final headerCrc = Crc32.compute(headerBytes) & 0xffff;
      out.writeUint16LE(headerCrc);
    }

    out
      ..writeBytes(compressed)
      ..writeUint32LE(crc)
      ..writeUint32LE(raw.length & 0xffffffff);
    return out.toBytes();
  }

  /// Decompresses an RFC 1952 GZIP stream (including multi-member concatenated
  /// GZIP streams) and returns the raw bytes.
  static Uint8List decodeBytes(
    List<int> bytes, {
    GZipOptions options = const GZipOptions(),
  }) {
    return decodeWithMetadata(bytes, options: options).bytes;
  }

  /// Decompresses a GZIP stream and returns both the decoded bytes and header
  /// [GZipMetadata].
  static GZipDecodedResult decodeWithMetadata(
    List<int> bytes, {
    GZipOptions options = const GZipOptions(),
  }) {
    final input = asUint8List(bytes);
    if (input.length < 18) {
      throw const ArchiveFormatException(
        'GZIP stream is too short (minimum 18 bytes).',
        offset: 0,
      );
    }

    final policy = options.securityPolicy;
    final reader = ByteReader(input);
    final combined = ByteWriter(input.length * 2);
    GZipMetadata? firstMetadata;

    while (!reader.isEof) {
      final memberStart = reader.offset;
      final id1 = reader.readUint8();
      final id2 = reader.readUint8();
      if (id1 != 0x1f || id2 != 0x8b) {
        throw ArchiveFormatException(
          'Invalid GZIP magic header: 0x${id1.toRadixString(16)} '
          '0x${id2.toRadixString(16)}.',
          offset: memberStart,
        );
      }

      final cm = reader.readUint8();
      if (cm != 8) {
        throw ArchiveFormatException(
          'Unsupported GZIP compression method $cm (expected 8).',
          offset: memberStart + 2,
        );
      }

      final flg = reader.readUint8();
      if ((flg & 0xe0) != 0) {
        throw ArchiveFormatException(
          'Reserved GZIP header flags are set (FLG=0x${flg.toRadixString(16)}).',
          offset: memberStart + 3,
        );
      }

      final mtimeRaw = reader.readUint32LE();
      reader.skip(1); // XFL
      final os = reader.readUint8();

      Uint8List? extra;
      if ((flg & _fextra) != 0) {
        final xlen = reader.readUint16LE();
        extra = reader.readBytesCopy(xlen);
      }

      String? filename;
      if ((flg & _fname) != 0) {
        filename = latin1.decode(reader.readNullTerminatedBytes());
      }

      String? comment;
      if ((flg & _fcomment) != 0) {
        comment = latin1.decode(reader.readNullTerminatedBytes());
      }

      if ((flg & _fhcrc) != 0) {
        final headerEnd = reader.offset;
        final expectedHcrc = reader.readUint16LE();
        if (policy.strictChecksum) {
          final actualHcrc =
              Crc32.compute(input, memberStart, headerEnd) & 0xffff;
          if (actualHcrc != expectedHcrc) {
            throw ArchiveChecksumException(
              'GZIP header CRC-16 mismatch.',
              expected: expectedHcrc,
              actual: actualHcrc,
              offset: headerEnd,
            );
          }
        }
      }

      firstMetadata ??= GZipMetadata(
        filename: filename,
        comment: comment,
        modifiedTime: mtimeRaw == 0
            ? null
            : DateTime.fromMillisecondsSinceEpoch(mtimeRaw * 1000, isUtc: true),
        extra: extra,
        os: os,
      );

      final deflateStart = reader.offset;
      final remainingLimit = policy.effectiveSingleStreamLimit(
        alreadyDecoded: combined.length,
      );
      final inflated = DeflateInflater.inflateWithCount(
        input,
        offset: deflateStart,
        end: input.length,
        maxOutputSize: remainingLimit,
        entryName: filename,
      );

      reader.offset = deflateStart + inflated.bytesConsumed;
      final trailerOffset = reader.offset;
      final expectedCrc = reader.readUint32LE();
      final expectedIsize = reader.readUint32LE();

      final memberCompressedLen = reader.offset - memberStart;
      policy.checkCompressionRatio(
        compressedSize: memberCompressedLen,
        uncompressedSize: inflated.bytes.length,
        entryName: filename,
      );

      if (policy.strictChecksum) {
        final actualCrc = Crc32.compute(inflated.bytes);
        if (actualCrc != expectedCrc) {
          throw ArchiveChecksumException(
            'GZIP CRC-32 checksum mismatch.',
            expected: expectedCrc,
            actual: actualCrc,
            entryName: filename,
            offset: trailerOffset,
          );
        }
        final actualIsize = inflated.bytes.length & 0xffffffff;
        if (actualIsize != expectedIsize) {
          throw ArchiveChecksumException(
            'GZIP ISIZE length mismatch.',
            expected: expectedIsize,
            actual: actualIsize,
            entryName: filename,
            offset: trailerOffset + 4,
          );
        }
      }

      combined.writeBytes(inflated.bytes);
    }

    return GZipDecodedResult(
      bytes: combined.toBytes(),
      metadata: firstMetadata ?? const GZipMetadata(),
    );
  }
}

final class _GZipEncoder extends Converter<List<int>, List<int>> {
  const _GZipEncoder(this.options);

  final GZipOptions options;

  @override
  Uint8List convert(List<int> input) =>
      GZipPlusCodec.encodeBytes(input, options: options);

  @override
  Sink<List<int>> startChunkedConversion(Sink<List<int>> sink) =>
      _GZipBufferedSink(sink, convert);
}

final class _GZipDecoder extends Converter<List<int>, List<int>> {
  const _GZipDecoder(this.options);

  final GZipOptions options;

  @override
  Uint8List convert(List<int> input) =>
      GZipPlusCodec.decodeBytes(input, options: options);

  @override
  Sink<List<int>> startChunkedConversion(Sink<List<int>> sink) =>
      _GZipBufferedSink(sink, convert);
}

final class _GZipBufferedSink implements Sink<List<int>> {
  _GZipBufferedSink(this._outSink, this._transform);

  final Sink<List<int>> _outSink;
  final Uint8List Function(List<int>) _transform;
  final ByteWriter _buffer = ByteWriter();

  @override
  void add(List<int> data) => _buffer.writeBytes(data);

  @override
  void close() {
    _outSink.add(_transform(_buffer.toBytesView()));
    _outSink.close();
  }
}

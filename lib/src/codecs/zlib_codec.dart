import 'dart:convert';
import 'dart:typed_data';

import '../core/archive_exceptions.dart';
import '../core/archive_options.dart';
import '../core/archive_security.dart';
import '../util/byte_buffer.dart';
import '../util/checksums.dart';
import 'deflate/deflater.dart';
import 'deflate/inflater.dart';

/// Pure Dart `dart:convert` [Codec] for raw RFC 1951 DEFLATE streams.
final class DeflatePlusCodec extends Codec<List<int>, List<int>> {
  /// Creates a [DeflatePlusCodec].
  const DeflatePlusCodec({
    this.level = CompressionLevel.balanced,
    this.securityPolicy = ArchiveSecurityPolicy.standard,
  });

  /// Compression level used by [encoder].
  final CompressionLevel level;

  /// Security policy enforced by [decoder].
  final ArchiveSecurityPolicy securityPolicy;

  @override
  Converter<List<int>, List<int>> get encoder => _DeflateEncoder(level);

  @override
  Converter<List<int>, List<int>> get decoder =>
      _DeflateDecoder(securityPolicy);

  /// Compresses [bytes] using raw RFC 1951 DEFLATE.
  static Uint8List encodeBytes(
    List<int> bytes, {
    CompressionLevel level = CompressionLevel.balanced,
  }) {
    return DeflateDeflater.deflate(asUint8List(bytes), level: level.level);
  }

  /// Decompresses raw RFC 1951 DEFLATE [bytes].
  static Uint8List decodeBytes(
    List<int> bytes, {
    ArchiveSecurityPolicy securityPolicy = ArchiveSecurityPolicy.standard,
  }) {
    final input = asUint8List(bytes);
    final decoded = DeflateInflater.inflate(
      input,
      maxOutputSize: securityPolicy.effectiveSingleStreamLimit(),
    );
    securityPolicy.checkCompressionRatio(
      compressedSize: input.length,
      uncompressedSize: decoded.length,
    );
    return decoded;
  }
}

final class _DeflateEncoder extends Converter<List<int>, List<int>> {
  const _DeflateEncoder(this.level);

  final CompressionLevel level;

  @override
  Uint8List convert(List<int> input) =>
      DeflatePlusCodec.encodeBytes(input, level: level);

  @override
  Sink<List<int>> startChunkedConversion(Sink<List<int>> sink) =>
      _BufferedSink(sink, convert);
}

final class _DeflateDecoder extends Converter<List<int>, List<int>> {
  const _DeflateDecoder(this.securityPolicy);

  final ArchiveSecurityPolicy securityPolicy;

  @override
  Uint8List convert(List<int> input) =>
      DeflatePlusCodec.decodeBytes(input, securityPolicy: securityPolicy);

  @override
  Sink<List<int>> startChunkedConversion(Sink<List<int>> sink) =>
      _BufferedSink(sink, convert);
}

/// Pure Dart RFC 1950 ZLIB [Codec] supporting streaming via `dart:convert`.
final class ZLibPlusCodec extends Codec<List<int>, List<int>> {
  /// Creates a [ZLibPlusCodec] with the given [options].
  const ZLibPlusCodec({this.options = const ZLibOptions()});

  /// Encoding and decoding configuration.
  final ZLibOptions options;

  @override
  Converter<List<int>, List<int>> get encoder => _ZLibEncoder(options);

  @override
  Converter<List<int>, List<int>> get decoder => _ZLibDecoder(options);

  /// Compresses [bytes] into an RFC 1950 ZLIB stream.
  static Uint8List encodeBytes(
    List<int> bytes, {
    ZLibOptions options = const ZLibOptions(),
  }) {
    final raw = asUint8List(bytes);
    final compressed = DeflateDeflater.deflate(raw, level: options.level.level);
    final adler = Adler32.compute(raw);

    // CMF: CM=8 (DEFLATE), CINFO=7 (32 KiB window) => 0x78.
    const cmf = 0x78;
    final flevel = switch (options.level) {
      CompressionLevel.none || CompressionLevel.fastest => 0,
      CompressionLevel.fast => 1,
      CompressionLevel.balanced => 2,
      CompressionLevel.high || CompressionLevel.best => 3,
    };
    var flg = flevel << 6;
    final rem = ((cmf << 8) | flg) % 31;
    if (rem != 0) {
      flg += 31 - rem;
    }

    final writer = ByteWriter(compressed.length + 6)
      ..writeUint8(cmf)
      ..writeUint8(flg)
      ..writeBytes(compressed)
      ..writeUint32BE(adler);
    return writer.toBytes();
  }

  /// Decompresses an RFC 1950 ZLIB stream while enforcing
  /// [ZLibOptions.securityPolicy].
  static Uint8List decodeBytes(
    List<int> bytes, {
    ZLibOptions options = const ZLibOptions(),
  }) {
    final input = asUint8List(bytes);
    if (input.length < 6) {
      throw const ArchiveFormatException(
        'ZLIB stream is too short (minimum 6 bytes).',
        offset: 0,
      );
    }

    final cmf = input[0];
    final flg = input[1];
    final cm = cmf & 0x0f;
    final cinfo = cmf >>> 4;

    if (cm != 8) {
      throw ArchiveFormatException(
        'Unsupported ZLIB compression method $cm (expected 8).',
        offset: 0,
      );
    }
    if (cinfo > 7) {
      throw ArchiveFormatException(
        'Invalid ZLIB window size CINFO=$cinfo.',
        offset: 0,
      );
    }
    if (((cmf << 8) | flg) % 31 != 0) {
      throw const ArchiveFormatException(
        'Invalid ZLIB header check bits (FCHECK failed).',
        offset: 1,
      );
    }
    if ((flg & 0x20) != 0) {
      throw const ArchiveFormatException(
        'ZLIB preset dictionaries (FDICT) are not supported.',
        offset: 1,
      );
    }

    final policy = options.securityPolicy;
    final result = DeflateInflater.inflateWithCount(
      input,
      offset: 2,
      end: input.length - 4,
      maxOutputSize: policy.effectiveSingleStreamLimit(),
    );

    final trailerOffset = 2 + result.bytesConsumed;
    if (trailerOffset + 4 > input.length) {
      throw ArchiveFormatException(
        'Truncated ZLIB Adler-32 trailer.',
        offset: trailerOffset,
      );
    }

    policy.checkCompressionRatio(
      compressedSize: input.length,
      uncompressedSize: result.bytes.length,
    );

    if (policy.strictChecksum) {
      final expectedAdler =
          ((input[trailerOffset] << 24) |
              (input[trailerOffset + 1] << 16) |
              (input[trailerOffset + 2] << 8) |
              input[trailerOffset + 3]) &
          0xffffffff;
      final actualAdler = Adler32.compute(result.bytes);
      if (actualAdler != expectedAdler) {
        throw ArchiveChecksumException(
          'ZLIB Adler-32 checksum mismatch.',
          expected: expectedAdler,
          actual: actualAdler,
          offset: trailerOffset,
        );
      }
    }

    return result.bytes;
  }
}

final class _ZLibEncoder extends Converter<List<int>, List<int>> {
  const _ZLibEncoder(this.options);

  final ZLibOptions options;

  @override
  Uint8List convert(List<int> input) =>
      ZLibPlusCodec.encodeBytes(input, options: options);

  @override
  Sink<List<int>> startChunkedConversion(Sink<List<int>> sink) =>
      _BufferedSink(sink, convert);
}

final class _ZLibDecoder extends Converter<List<int>, List<int>> {
  const _ZLibDecoder(this.options);

  final ZLibOptions options;

  @override
  Uint8List convert(List<int> input) =>
      ZLibPlusCodec.decodeBytes(input, options: options);

  @override
  Sink<List<int>> startChunkedConversion(Sink<List<int>> sink) =>
      _BufferedSink(sink, convert);
}

final class _BufferedSink implements Sink<List<int>> {
  _BufferedSink(this._outSink, this._transform);

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

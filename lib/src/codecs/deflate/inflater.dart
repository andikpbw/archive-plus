import 'dart:typed_data';

import '../../core/archive_exceptions.dart';
import '../../util/bit_reader.dart';
import 'deflate_tables.dart';
import 'huffman_tree.dart';

/// Result returned by [DeflateInflater.inflateWithCount], exposing both the
/// decompressed [bytes] and the exact number of compressed [bytesConsumed].
final class InflateResult {
  /// Creates an [InflateResult].
  const InflateResult({required this.bytes, required this.bytesConsumed});

  /// Decompressed payload bytes.
  final Uint8List bytes;

  /// Number of input bytes consumed from the start offset to the end of the
  /// DEFLATE stream (byte-aligned).
  final int bytesConsumed;
}

/// Pure Dart RFC 1951 raw DEFLATE decompressor with built-in output size caps
/// to prevent zip-bomb memory exhaustion.
final class DeflateInflater {
  DeflateInflater._();

  /// Decompresses a raw RFC 1951 DEFLATE stream from [input].
  ///
  /// Enforces [maxOutputSize] incrementally during inflation, throwing
  /// [ArchiveSecurityException] immediately if the decompressed stream would
  /// exceed the ceiling.
  static Uint8List inflate(
    Uint8List input, {
    int offset = 0,
    int? end,
    int? maxOutputSize,
    String? entryName,
  }) {
    return inflateWithCount(
      input,
      offset: offset,
      end: end,
      maxOutputSize: maxOutputSize,
      entryName: entryName,
    ).bytes;
  }

  /// Decompresses a raw RFC 1951 DEFLATE stream and also reports how many
  /// compressed bytes were consumed.
  static InflateResult inflateWithCount(
    Uint8List input, {
    int offset = 0,
    int? end,
    int? maxOutputSize,
    String? entryName,
  }) {
    final reader = LsbBitReader(input, offset: offset, end: end);
    final initialCap = (input.length - offset) * 2;
    var out = Uint8List(initialCap < 256 ? 256 : initialCap.clamp(256, 65536));
    var outLen = 0;

    void ensureOut(int additional) {
      final needed = outLen + additional;
      if (maxOutputSize != null && needed > maxOutputSize) {
        throw ArchiveSecurityException(
          'Decompressed size ($needed bytes) exceeds policy limit '
          '($maxOutputSize bytes).',
          violation: ArchiveSecurityViolation.entrySizeLimitExceeded,
          entryName: entryName,
          offset: reader.byteOffset,
        );
      }
      if (needed <= out.length) {
        return;
      }
      var newCap = out.length * 2;
      while (newCap < needed) {
        newCap *= 2;
      }
      if (maxOutputSize != null && newCap > maxOutputSize) {
        newCap = maxOutputSize;
      }
      final next = Uint8List(newCap);
      next.setRange(0, outLen, out);
      out = next;
    }

    var isFinal = false;
    while (!isFinal) {
      isFinal = reader.readBits(1) == 1;
      final blockType = reader.readBits(2);

      if (blockType == 0) {
        // Uncompressed (stored) block.
        final len = reader.readAlignedUint16LE();
        final nlen = reader.readAlignedUint16LE();
        if ((len ^ 0xffff) != nlen) {
          throw ArchiveFormatException(
            'Corrupted DEFLATE stored block length check '
            '(LEN=$len, NLEN=$nlen).',
            entryName: entryName,
            offset: reader.byteOffset,
          );
        }
        ensureOut(len);
        reader.readAlignedBytes(out, outLen, len);
        outLen += len;
      } else if (blockType == 1 || blockType == 2) {
        late final DeflateHuffmanDecoder litLenTree;
        late final DeflateHuffmanDecoder distTree;

        if (blockType == 1) {
          litLenTree = DeflateHuffmanDecoder.fixedLitLen;
          distTree = DeflateHuffmanDecoder.fixedDist;
        } else {
          final hlit = reader.readBits(5) + 257;
          final hdist = reader.readBits(5) + 1;
          final hclen = reader.readBits(4) + 4;
          if (hlit > 286 || hdist > 30) {
            throw ArchiveFormatException(
              'Invalid dynamic DEFLATE header (HLIT=$hlit, HDIST=$hdist).',
              entryName: entryName,
              offset: reader.byteOffset,
            );
          }

          final codeLengths = Uint8List(19);
          for (var i = 0; i < hclen; i++) {
            codeLengths[DeflateTables.codeLengthOrder[i]] = reader.readBits(3);
          }
          final codeLenTree = DeflateHuffmanDecoder.fromLengths(
            codeLengths,
            maxAllowedBits: 7,
          );

          final totalLengths = hlit + hdist;
          final allLengths = Uint8List(totalLengths);
          var idx = 0;
          while (idx < totalLengths) {
            final sym = codeLenTree.decode(reader);
            if (sym < 16) {
              allLengths[idx++] = sym;
            } else if (sym == 16) {
              if (idx == 0) {
                throw ArchiveFormatException(
                  'DEFLATE repeat code 16 with no preceding code length.',
                  entryName: entryName,
                  offset: reader.byteOffset,
                );
              }
              final repeat = reader.readBits(2) + 3;
              if (idx + repeat > totalLengths) {
                throw ArchiveFormatException(
                  'DEFLATE code length repeat overflow.',
                  entryName: entryName,
                  offset: reader.byteOffset,
                );
              }
              final prev = allLengths[idx - 1];
              allLengths.fillRange(idx, idx + repeat, prev);
              idx += repeat;
            } else if (sym == 17) {
              final repeat = reader.readBits(3) + 3;
              if (idx + repeat > totalLengths) {
                throw ArchiveFormatException(
                  'DEFLATE zero-repeat code 17 overflow.',
                  entryName: entryName,
                  offset: reader.byteOffset,
                );
              }
              idx += repeat; // Uint8List is already zero-initialized.
            } else if (sym == 18) {
              final repeat = reader.readBits(7) + 11;
              if (idx + repeat > totalLengths) {
                throw ArchiveFormatException(
                  'DEFLATE zero-repeat code 18 overflow.',
                  entryName: entryName,
                  offset: reader.byteOffset,
                );
              }
              idx += repeat;
            } else {
              throw ArchiveFormatException(
                'Invalid code-length symbol $sym.',
                entryName: entryName,
                offset: reader.byteOffset,
              );
            }
          }

          if (allLengths[256] == 0) {
            throw ArchiveFormatException(
              'Dynamic DEFLATE block missing end-of-block symbol 256.',
              entryName: entryName,
              offset: reader.byteOffset,
            );
          }

          litLenTree = DeflateHuffmanDecoder.fromLengths(
            Uint8List.sublistView(allLengths, 0, hlit),
          );
          distTree = DeflateHuffmanDecoder.fromLengths(
            Uint8List.sublistView(allLengths, hlit, totalLengths),
            allowEmpty: true,
          );
        }

        // Decode literal / length-distance symbols until end-of-block (256).
        while (true) {
          final sym = litLenTree.decode(reader);
          if (sym < 256) {
            ensureOut(1);
            out[outLen++] = sym;
          } else if (sym == 256) {
            break;
          } else {
            final lenIndex = sym - 257;
            if (lenIndex >= 29) {
              throw ArchiveFormatException(
                'Invalid DEFLATE length symbol $sym.',
                entryName: entryName,
                offset: reader.byteOffset,
              );
            }
            final matchLen =
                DeflateTables.lengthBase[lenIndex] +
                reader.readBits(DeflateTables.lengthExtraBits[lenIndex]);

            final distSym = distTree.decode(reader);
            if (distSym >= 30) {
              throw ArchiveFormatException(
                'Invalid DEFLATE distance symbol $distSym.',
                entryName: entryName,
                offset: reader.byteOffset,
              );
            }
            final distance =
                DeflateTables.distBase[distSym] +
                reader.readBits(DeflateTables.distExtraBits[distSym]);
            if (distance > outLen) {
              throw ArchiveFormatException(
                'DEFLATE back-reference distance ($distance) exceeds decoded '
                'history ($outLen).',
                entryName: entryName,
                offset: reader.byteOffset,
              );
            }

            ensureOut(matchLen);
            var src = outLen - distance;
            if (distance >= matchLen) {
              out.setRange(outLen, outLen + matchLen, out, src);
              outLen += matchLen;
            } else if (distance == 1) {
              final fillByte = out[src];
              out.fillRange(outLen, outLen + matchLen, fillByte);
              outLen += matchLen;
            } else {
              for (var i = 0; i < matchLen; i++) {
                out[outLen++] = out[src++];
              }
            }
          }
        }
      } else {
        throw ArchiveFormatException(
          'Invalid DEFLATE block type 3.',
          entryName: entryName,
          offset: reader.byteOffset,
        );
      }
    }

    reader.alignToByte();
    final resultBytes = Uint8List(outLen);
    resultBytes.setRange(0, outLen, out);
    return InflateResult(
      bytes: resultBytes,
      bytesConsumed: reader.byteOffset - offset,
    );
  }
}

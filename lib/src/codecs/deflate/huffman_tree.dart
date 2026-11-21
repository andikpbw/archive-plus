import 'dart:typed_data';

import '../../core/archive_exceptions.dart';
import '../../util/bit_reader.dart';
import 'deflate_tables.dart';

/// Fast canonical Huffman decoder for RFC 1951 DEFLATE streams.
///
/// Uses a 9-bit direct lookup table for common short codes (`<= 9` bits) and
/// falls back to canonical code-range decoding for longer codes (`10..15` bits).
final class DeflateHuffmanDecoder {
  DeflateHuffmanDecoder._({
    required Uint16List fastTable,
    required Int32List counts,
    required Int32List firstCode,
    required Int32List firstSymbol,
    required Uint16List symbols,
    required int maxBits,
  }) : _fastTable = fastTable,
       _counts = counts,
       _firstCode = firstCode,
       _firstSymbol = firstSymbol,
       _symbols = symbols,
       _maxBits = maxBits;

  static const int _fastBits = 9;
  static const int _fastSize = 1 << _fastBits;
  static const int _fastMask = _fastSize - 1;

  final Uint16List _fastTable;
  final Int32List _counts;
  final Int32List _firstCode;
  final Int32List _firstSymbol;
  final Uint16List _symbols;
  final int _maxBits;

  /// Cached decoder for RFC 1951 fixed literal/length codes.
  static final DeflateHuffmanDecoder fixedLitLen =
      DeflateHuffmanDecoder.fromLengths(DeflateTables.fixedLitLenLengths);

  /// Cached decoder for RFC 1951 fixed distance codes.
  static final DeflateHuffmanDecoder fixedDist =
      DeflateHuffmanDecoder.fromLengths(DeflateTables.fixedDistLengths);

  /// Builds a [DeflateHuffmanDecoder] from canonical symbol bit [lengths].
  ///
  /// Throws [ArchiveFormatException] if the Huffman tree is oversubscribed.
  factory DeflateHuffmanDecoder.fromLengths(
    List<int> lengths, {
    int maxAllowedBits = 15,
    bool allowEmpty = false,
  }) {
    final counts = Int32List(maxAllowedBits + 1);
    var maxBits = 0;
    var nonZero = 0;

    for (var i = 0; i < lengths.length; i++) {
      final len = lengths[i];
      if (len < 0 || len > maxAllowedBits) {
        throw ArchiveFormatException(
          'Invalid Huffman code length $len (max $maxAllowedBits).',
        );
      }
      if (len > 0) {
        counts[len]++;
        nonZero++;
        if (len > maxBits) {
          maxBits = len;
        }
      }
    }

    if (nonZero == 0) {
      if (!allowEmpty) {
        throw const ArchiveFormatException('Empty Huffman code tree.');
      }
      return DeflateHuffmanDecoder._(
        fastTable: Uint16List(_fastSize),
        counts: counts,
        firstCode: Int32List(maxAllowedBits + 1),
        firstSymbol: Int32List(maxAllowedBits + 1),
        symbols: Uint16List(0),
        maxBits: 0,
      );
    }

    // Validate Kraft inequality (cannot be oversubscribed).
    var left = 1;
    for (var bits = 1; bits <= maxBits; bits++) {
      left <<= 1;
      left -= counts[bits];
      if (left < 0) {
        throw const ArchiveFormatException(
          'Oversubscribed canonical Huffman tree.',
        );
      }
    }

    final firstCode = Int32List(maxAllowedBits + 1);
    final firstSymbol = Int32List(maxAllowedBits + 1);
    final offsets = Int32List(maxAllowedBits + 1);

    var code = 0;
    var symIndex = 0;
    for (var bits = 1; bits <= maxBits; bits++) {
      firstCode[bits] = code;
      firstSymbol[bits] = symIndex;
      offsets[bits] = symIndex;
      code = (code + counts[bits]) << 1;
      symIndex += counts[bits];
    }

    final symbols = Uint16List(nonZero);
    final fastTable = Uint16List(_fastSize);

    for (var sym = 0; sym < lengths.length; sym++) {
      final len = lengths[sym];
      if (len == 0) {
        continue;
      }
      final idx = offsets[len]++;
      symbols[idx] = sym;
      if (len <= _fastBits) {
        final canonicalCode = firstCode[len] + (idx - firstSymbol[len]);
        final reversed = DeflateTables.reverseBits(canonicalCode, len);
        final entry = (sym << 4) | len;
        final step = 1 << len;
        for (var fill = reversed; fill < _fastSize; fill += step) {
          fastTable[fill] = entry;
        }
      }
    }

    return DeflateHuffmanDecoder._(
      fastTable: fastTable,
      counts: counts,
      firstCode: firstCode,
      firstSymbol: firstSymbol,
      symbols: symbols,
      maxBits: maxBits,
    );
  }

  /// Decodes the next symbol from [reader].
  @pragma('vm:prefer-inline')
  int decode(LsbBitReader reader) {
    if (_maxBits == 0) {
      throw const ArchiveFormatException(
        'Attempted to decode symbol from an empty Huffman tree.',
      );
    }
    final peek = reader.peekBits(_fastBits);
    final fastEntry = _fastTable[peek & _fastMask];
    if (fastEntry != 0) {
      final len = fastEntry & 0x0f;
      reader.dropBits(len);
      return fastEntry >>> 4;
    }

    // Slow path for codes > 9 bits: read bit-by-bit as MSB-first canonical code.
    var code = 0;
    for (var len = 1; len <= _maxBits; len++) {
      code = (code << 1) | reader.readBits(1);
      final count = _counts[len];
      final diff = code - _firstCode[len];
      if (diff >= 0 && diff < count) {
        return _symbols[_firstSymbol[len] + diff];
      }
    }

    throw ArchiveFormatException(
      'Invalid Huffman code encountered in DEFLATE stream.',
      offset: reader.byteOffset,
    );
  }
}

/// Encoded canonical Huffman table with bit-reversed LSB codes ready for
/// writing to an LSB bit stream.
final class DeflateHuffmanEncoder {
  /// Creates a [DeflateHuffmanEncoder] from canonical bit [lengths].
  factory DeflateHuffmanEncoder.fromLengths(List<int> lengths) {
    final lenList = Uint8List.fromList(lengths);
    final codes = Uint16List(lengths.length);
    var maxBits = 0;
    for (final len in lenList) {
      if (len > maxBits) {
        maxBits = len;
      }
    }
    if (maxBits == 0) {
      return DeflateHuffmanEncoder._(codes, lenList);
    }

    final blCount = Int32List(maxBits + 1);
    for (final len in lenList) {
      if (len > 0) {
        blCount[len]++;
      }
    }

    final nextCode = Int32List(maxBits + 1);
    var code = 0;
    for (var bits = 1; bits <= maxBits; bits++) {
      code = (code + blCount[bits - 1]) << 1;
      nextCode[bits] = code;
    }

    for (var sym = 0; sym < lenList.length; sym++) {
      final len = lenList[sym];
      if (len > 0) {
        codes[sym] = DeflateTables.reverseBits(nextCode[len]++, len);
      }
    }

    return DeflateHuffmanEncoder._(codes, lenList);
  }

  DeflateHuffmanEncoder._(this.codes, this.lengths);

  /// Cached fixed literal/length encoder.
  static final DeflateHuffmanEncoder fixedLitLen =
      DeflateHuffmanEncoder.fromLengths(DeflateTables.fixedLitLenLengths);

  /// Cached fixed distance encoder.
  static final DeflateHuffmanEncoder fixedDist =
      DeflateHuffmanEncoder.fromLengths(DeflateTables.fixedDistLengths);

  /// Bit-reversed LSB codes indexed by symbol.
  final Uint16List codes;

  /// Bit lengths indexed by symbol.
  final Uint8List lengths;

  /// Computes optimal length-limited Huffman bit lengths (`<= maxBits`) for
  /// [frequencies] using the exact Package-Merge algorithm.
  static Uint8List computeLengths(List<int> frequencies, int maxBits) {
    final numSymbols = frequencies.length;
    final lengths = Uint8List(numSymbols);

    final activeSymbols = <int>[];
    for (var i = 0; i < numSymbols; i++) {
      if (frequencies[i] > 0) {
        activeSymbols.add(i);
      }
    }

    if (activeSymbols.isEmpty) {
      return lengths;
    }
    if (activeSymbols.length == 1) {
      lengths[activeSymbols[0]] = 1;
      return lengths;
    }
    if (activeSymbols.length == 2) {
      lengths[activeSymbols[0]] = 1;
      lengths[activeSymbols[1]] = 1;
      return lengths;
    }

    // Sort active symbols by ascending frequency (tie-break by symbol index).
    activeSymbols.sort((a, b) {
      final cmp = frequencies[a].compareTo(frequencies[b]);
      return cmp != 0 ? cmp : a.compareTo(b);
    });

    final n = activeSymbols.length;
    // Clamp maxBits to at most n - 1 since a tree on n leaves never needs more.
    final effectiveMaxBits = maxBits < (n - 1) ? maxBits : (n - 1);

    // Base coin list for every level: each leaf has weight = frequency.
    var prevPackages = <_PmNode>[];
    for (var level = 0; level < effectiveMaxBits; level++) {
      final coins = <_PmNode>[
        for (var i = 0; i < n; i++)
          _PmNode.leaf(activeSymbols[i], frequencies[activeSymbols[i]]),
      ];
      // Merge sorted coins with sorted packages from previous level.
      final merged = _mergeSorted(coins, prevPackages);

      if (level == effectiveMaxBits - 1) {
        // Select the lightest `2 * n - 2` items on the final level.
        final take = 2 * n - 2;
        for (var i = 0; i < take; i++) {
          _accumulateLeaves(merged[i], lengths);
        }
        break;
      }

      // Pair adjacent items to form packages for the next level.
      final pairCount = merged.length >> 1;
      final nextPackages = <_PmNode>[];
      for (var i = 0; i < pairCount; i++) {
        final left = merged[i * 2];
        final right = merged[i * 2 + 1];
        nextPackages.add(
          _PmNode.branch(left.weight + right.weight, left, right),
        );
      }
      prevPackages = nextPackages;
    }

    return lengths;
  }

  static List<_PmNode> _mergeSorted(List<_PmNode> a, List<_PmNode> b) {
    final out = <_PmNode>[];
    var i = 0;
    var j = 0;
    while (i < a.length && j < b.length) {
      if (a[i].weight <= b[j].weight) {
        out.add(a[i++]);
      } else {
        out.add(b[j++]);
      }
    }
    while (i < a.length) {
      out.add(a[i++]);
    }
    while (j < b.length) {
      out.add(b[j++]);
    }
    return out;
  }

  static void _accumulateLeaves(_PmNode node, Uint8List lengths) {
    if (node.symbol >= 0) {
      lengths[node.symbol]++;
      return;
    }
    _accumulateLeaves(node.left!, lengths);
    _accumulateLeaves(node.right!, lengths);
  }
}

final class _PmNode {
  const _PmNode.leaf(this.symbol, this.weight) : left = null, right = null;
  const _PmNode.branch(this.weight, this.left, this.right) : symbol = -1;

  final int symbol;
  final int weight;
  final _PmNode? left;
  final _PmNode? right;
}

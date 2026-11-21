import 'dart:typed_data';

/// RFC 1951 DEFLATE static lookup tables for lengths, distances, and fixed
/// Huffman codes.
final class DeflateTables {
  DeflateTables._();

  /// Base match lengths for symbols 257..285.
  static const List<int> lengthBase = <int>[
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    13,
    15,
    17,
    19,
    23,
    27,
    31,
    35,
    43,
    51,
    59,
    67,
    83,
    99,
    115,
    131,
    163,
    195,
    227,
    258,
  ];

  /// Extra bit counts for length symbols 257..285.
  static const List<int> lengthExtraBits = <int>[
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    1,
    1,
    1,
    2,
    2,
    2,
    2,
    3,
    3,
    3,
    3,
    4,
    4,
    4,
    4,
    5,
    5,
    5,
    5,
    0,
  ];

  /// Base distances for distance symbols 0..29.
  static const List<int> distBase = <int>[
    1,
    2,
    3,
    4,
    5,
    7,
    9,
    13,
    17,
    25,
    33,
    49,
    65,
    97,
    129,
    193,
    257,
    385,
    513,
    769,
    1025,
    1537,
    2049,
    3073,
    4097,
    6145,
    8193,
    12289,
    16385,
    24577,
  ];

  /// Extra bit counts for distance symbols 0..29.
  static const List<int> distExtraBits = <int>[
    0,
    0,
    0,
    0,
    1,
    1,
    2,
    2,
    3,
    3,
    4,
    4,
    5,
    5,
    6,
    6,
    7,
    7,
    8,
    8,
    9,
    9,
    10,
    10,
    11,
    11,
    12,
    12,
    13,
    13,
  ];

  /// Permutation order of the 19 code-length alphabet symbols in dynamic blocks.
  static const List<int> codeLengthOrder = <int>[
    16,
    17,
    18,
    0,
    8,
    7,
    9,
    6,
    10,
    5,
    11,
    4,
    12,
    3,
    13,
    2,
    14,
    1,
    15,
  ];

  /// Fixed Huffman literal/length bit lengths (RFC 1951 Section 3.2.6).
  static final Uint8List fixedLitLenLengths = _buildFixedLitLenLengths();

  /// Fixed Huffman distance bit lengths (32 symbols of 5 bits each).
  static final Uint8List fixedDistLengths = Uint8List(32)..fillRange(0, 32, 5);

  /// Direct lookup table mapping match length `3..258` to symbol index `0..28`.
  static final Uint8List lengthToCodeIndex = _buildLengthToCodeIndex();

  static Uint8List _buildFixedLitLenLengths() {
    final lengths = Uint8List(288);
    lengths.fillRange(0, 144, 8);
    lengths.fillRange(144, 256, 9);
    lengths.fillRange(256, 280, 7);
    lengths.fillRange(280, 288, 8);
    return lengths;
  }

  static Uint8List _buildLengthToCodeIndex() {
    final table = Uint8List(259);
    for (var code = 0; code < 28; code++) {
      final start = lengthBase[code];
      final end = lengthBase[code + 1];
      for (var len = start; len < end; len++) {
        table[len] = code;
      }
    }
    table[258] = 28;
    return table;
  }

  /// Maps a match [distance] (`1..32768`) to its RFC 1951 distance symbol
  /// (`0..29`).
  @pragma('vm:prefer-inline')
  static int distanceToCode(int distance) {
    // Binary search over 30 entries (max 5 comparisons).
    var lo = 0;
    var hi = 29;
    while (lo < hi) {
      final mid = (lo + hi + 1) >> 1;
      if (distBase[mid] <= distance) {
        lo = mid;
      } else {
        hi = mid - 1;
      }
    }
    return lo;
  }

  /// Reverses the lowest [bitLength] bits of [code] for LSB-first DEFLATE.
  @pragma('vm:prefer-inline')
  static int reverseBits(int code, int bitLength) {
    var result = 0;
    var value = code;
    for (var i = 0; i < bitLength; i++) {
      result = (result << 1) | (value & 1);
      value >>>= 1;
    }
    return result;
  }
}

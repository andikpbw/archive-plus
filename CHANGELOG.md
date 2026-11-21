## 1.0.0

* Initial stable release of `archive_plus` — a modern, lightweight, zero-dependency archive and compression library for Dart and Flutter.
* **Container Formats:**
  * PKWARE ZIP encoder & decoder supporting Store, DEFLATE, and BZip2 methods, ZIP64 structures, UTF-8 EFS filenames, UNIX permissions, Extended Timestamps (`0x5455`), Data Descriptors, Traditional PKWARE ZipCrypto password encryption, zero-decompression Central Directory inspection (`inspectZip`), and selective single-entry extraction (`extractZipEntry`).
  * POSIX USTAR, PAX Extended Header (`x`/`g`), and GNU LongName/LongLink (`L`/`K`) TAR encoder & decoder, plus one-liner `.tar.gz` and `.tar.bz2` APIs.
* **Pure Dart Compression Codecs:**
  * RFC 1951 raw DEFLATE (with Stored, Fixed Huffman, and optimal length-limited Package-Merge Dynamic Huffman block selection).
  * RFC 1950 ZLIB with Adler-32 verification.
  * RFC 1952 GZIP with full header metadata (`FNAME`, `FCOMMENT`, `FEXTRA`, `FHCRC`) and concatenated multi-member stream support.
  * Pure Dart BZip2 encoder and decoder with O(n log n) prefix-doubling BWT and multi-table Huffman coding.
  * Pure Dart LZ4 Frame Format (v1.6) encoder and decoder with XXH32 checksums and skippable frame support.
  * `dart:convert` `Codec` implementations for all single-stream compressors.
* **Security, Observability & Extensibility:**
  * Built-in `ArchiveSecurityPolicy` guarding against Zip-Slip path traversal, Zip-Bomb ratio/size exhaustion, symlink escapes, and checksum tampering.
  * Exhaustive Dart 3 `sealed class ArchiveException` error hierarchy.
  * Fluent `ArchiveBuilder`, glob-based `ArchiveFilter`, real-time `ArchiveProgress`, cooperative `ArchiveCancelToken`, `Archive.diff`, `Archive.stats`, `ArchiveFormatDetector`, and extensible `ArchiveCodecRegistry`.
  * Platform-adaptive `archive_plus_io.dart` providing `ArchiveFileSystem` and background `ArchiveIsolate` workers via Web/Wasm-safe conditional exports.

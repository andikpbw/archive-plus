/// Platform-aware entry point combining all core `archive_plus` APIs with
/// native `dart:io` file-system utilities (`ArchiveFileSystem`) and background
/// isolate workers (`ArchiveIsolate`).
///
/// Uses conditional exports so importing this library remains Web and
/// WebAssembly safe at compile time.
library;

export 'archive_plus.dart';
export 'src/io/archive_io_stub.dart'
    if (dart.library.io) 'src/io/archive_io_native.dart';

# unalz-rs

Slop coded. ALZ archive extractor (Korean compression format by ESTsoft/ALZip).

Both a library (`unalz_rs`) and a CLI binary (`unalz`).

## Build

```
cargo build --release
```

## Usage

```
unalz [-l] [-p] [-q] [-d DIR] [--pwd PASSWORD] archive.alz [file ...]
```

- `-l` -- list archive contents
- `-p` -- extract to stdout (pipe mode)
- `-q` -- quiet (suppress progress)
- `-d DIR` -- extract to directory
- `--pwd PASSWORD` -- set decryption password
- `file ...` -- extract only named files (default: all)

## Features

- [x] Store (uncompressed) extraction
- [x] Deflate extraction
- [ ] ALZ-modified bzip2 extraction
- [x] Multi-volume archives (.alz, .a00, .a01, ...)
- [ ] PKware ZIP traditional encryption (implemented, untested)
- [x] CP949/EUC-KR filename decoding to UTF-8
- [x] CRC32 verification
- [x] DOS timestamp preservation

## Format

See [docs/specification.md](docs/specification.md) for a reverse-engineered format specification.

## References

- [unalz](http://kippler.com/win/unalz/) -- original C/C++ implementation by kippler
- [OctopusET/unalz](https://github.com/OctopusET/unalz) -- reference C/C++ implementation (source archive)
- [ALZ on ArchiveTeam](http://fileformats.archiveteam.org/wiki/ALZ) -- format wiki entry

## License

BSD-2-Clause

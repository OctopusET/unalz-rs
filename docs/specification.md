# ALZ Archive Format

Slop coded. Reverse-engineered specification. No official documentation exists.

All multi-byte integers are little-endian unless stated otherwise.

## 1. Archive Layout

An ALZ archive consists of a sequence of tagged records identified by 4-byte signatures:

```
[ALZ File Header]
[Local File Header + File Data] *
[Central Directory Structure]
[End of Central Directory]
```

## 2. Signatures

| Signature (LE) | Description |
|-----------------|-------------|
| `0x015a4c41` | ALZ file header |
| `0x015a4c42` | Local file header |
| `0x015a4c43` | Central directory structure |
| `0x025a4c43` | End of central directory |

## 3. ALZ File Header

| Offset | Size | Description |
|--------|------|-------------|
| +0 | 4 | Signature `0x015a4c41` |
| +4 | 4 | Unknown |

## 4. Local File Header

### 4.1 Fixed Head (9 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| +0 | 2 | fileNameLength | Length of filename in bytes |
| +2 | 1 | fileAttribute | See 4.2 |
| +3 | 4 | fileTimeDate | DOS date/time, see 7 |
| +7 | 1 | fileDescriptor | See 4.3 |
| +8 | 1 | unknown | |

### 4.2 File Attribute

| Bit | Mask | Meaning |
|-----|------|---------|
| 0 | `0x01` | Read-only |
| 1 | `0x02` | Hidden |
| 4 | `0x10` | Directory |
| 5 | `0x20` | File |

### 4.3 File Descriptor

| Bits | Mask | Meaning |
|------|------|---------|
| 0 | `0x01` | Encrypted |
| 3 | `0x08` | Data descriptor present |
| 4-7 | `0xF0` | Size field byte width |

The high nibble `(fileDescriptor >> 4)` gives the byte width N of the compressed/uncompressed size fields:

| Value | N |
|-------|---|
| `0x00` | 0 (no variable part; directory entry) |
| `0x10` | 1 |
| `0x20` | 2 |
| `0x40` | 4 |
| `0x80` | 8 |

### 4.4 Variable Part (present when N > 0)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| +0 | 1 | compressionMethod | See 5 |
| +1 | 1 | unknown | |
| +2 | 4 | fileCRC | CRC32 of uncompressed data |
| +6 | N | compressedSize | LE integer, zero-padded to 64-bit |
| +6+N | N | uncompressedSize | LE integer, zero-padded to 64-bit |

### 4.5 Filename and Data

| Size | Field |
|------|-------|
| fileNameLength | Filename (CP949 or UTF-8) |
| 12 (if encrypted) | Encryption header, see 6 |
| compressedSize | File data |

## 5. Compression Methods

| Value | Method |
|-------|--------|
| 0 | Store (uncompressed) |
| 1 | ALZ-modified bzip2, see 5.1 |
| 2 | Raw DEFLATE (RFC 1951, no wrapper) |

### 5.1 ALZ-Modified bzip2

Standard bzip2 with the following changes:

| | Standard bzip2 | ALZ |
|-|---------------|-----|
| Stream header | `BZh[1-9]` (4 bytes) | Absent |
| Block size | From header | Hardcoded 9 (900K) |
| Block magic | `0x314159265359` (6 bytes) | `DLZ\x01` (4 bytes) |
| End magic | `0x177245385090` (6 bytes) | `DLZ\x02` (4 bytes) |
| Block CRC | 4 bytes | Absent |
| Randomization bit | 1 bit | Absent |
| Combined CRC | 4 bytes at end | Absent |
| origPtr | 24-bit big-endian | Unchanged |
| Huffman/MTF/BWT/RLE | Standard | Unchanged |

Block parsing:

```
Read 4 bytes: expect 'D' 'L' 'Z' [type]
  type == 0x01: data block
    Read origPtr (3 bytes, big-endian)
    Decode standard bzip2 block data (Huffman, MTF, BWT, RLE)
  type == 0x02: end of stream
```

## 6. Encryption

PKware ZIP traditional encryption (identical to ZIP 2.0).

### 6.1 Key State

Three 32-bit keys, initialized:

```
key[0] = 0x12345678
key[1] = 0x23456789
key[2] = 0x3456789A
```

Each password byte is processed through UpdateKeys (6.2).

### 6.2 UpdateKeys(c)

```
key[0] = CRC32_TABLE[(key[0] ^ c) & 0xFF] ^ (key[0] >> 8)
key[1] = (key[1] + (key[0] & 0xFF)) * 134775813 + 1
key[2] = CRC32_TABLE[(key[2] ^ (key[1] >> 24)) & 0xFF] ^ (key[2] >> 8)
```

CRC32 polynomial: `0xEDB88320`.

### 6.3 DecryptByte()

```
temp = (key[2] | 2) as u16
return (temp * (temp ^ 1)) >> 8
```

### 6.4 Decryption

For each ciphertext byte:

```
plain = cipher ^ DecryptByte()
UpdateKeys(plain)
```

### 6.5 Password Validation

The 12-byte encryption header (after filename) is decrypted. The last decrypted byte must equal:

- `(fileCRC >> 24)` normally
- `(fileTimeDate >> 8)` if data descriptor flag is set

On match, re-initialize keys with the password and re-process the 12-byte header to establish the correct key state for data decryption.

## 7. DOS Date/Time Format

```
Bits  0-4:  seconds / 2
Bits  5-10: minutes
Bits 11-15: hours
Bits 16-20: day
Bits 21-24: month
Bits 25-31: year - 1980
```

## 8. Central Directory Structure

| Offset | Size | Description |
|--------|------|-------------|
| +0 | 4 | Signature `0x015a4c43` |
| +4 | 4 | Unknown |
| +8 | 4 | Unknown |
| +12 | 4 | Unknown |

Not used for extraction. The archive is parsed sequentially.

## 9. End of Central Directory

| Offset | Size | Description |
|--------|------|-------------|
| +0 | 4 | Signature `0x025a4c43` |

No additional fields.

## 10. Multi-Volume Archives

### 10.1 Volume Naming

| Volume | Extension |
|--------|-----------|
| 0 | `.alz` |
| 1 | `.a00` |
| 2 | `.a01` |
| ... | |
| 100 | `.a99` |
| 101 | `.b00` |
| ... | |

For volume index i > 0: letter = `'a' + (i-1)/100`, number = `(i-1) % 100`, extension = `{letter}{number:02}`. Maximum 1000 volumes.

### 10.2 Volume Layout

First volume (`.alz`):

```
[data...]
[16-byte tail]
```

Middle volumes:

```
[8-byte header]
[data...]
[16-byte tail]
```

Last volume:

```
[8-byte header]  (unless it is also the first)
[data...]
```

The header and tail are opaque metadata skipped during I/O. Usable data per volume = `file_size - header_size - tail_size`.

### 10.3 Constants

| Name | Value |
|------|-------|
| Header size | 8 bytes |
| Tail size | 16 bytes |
| Max volumes | 1000 |

## 11. CRC32

Standard CRC32 with polynomial `0xEDB88320`. Computed over decompressed (and decrypted) file data. Verified against `fileCRC` from the local file header.

## 12. Filename Encoding

Filenames are typically CP949 (a superset of EUC-KR). If the bytes are valid UTF-8, they should be interpreted as UTF-8. Otherwise, decode as CP949.

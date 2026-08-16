# NGM Patch Format (`.nxdlpatch`)

Reverse-engineered from `reference/Program.cs` and the sample files in
`reference/` (`Maplestory_Classic.exe.old`, `Maplestory_Classic.exe.new`,
`TWFwbGVzdG9yeV9DbGFzc2ljLmV4ZQ==.nxdlpatch`). There is no public
documentation of this format.

## Overview

NGM patching is file-based: each changed file gets its own `.nxdlpatch`
file that transforms the *old* version of that file into the *new* version.
The patch can reference arbitrary byte ranges of the old file ("copy from
old") and embed new bytes literally ("copy from patch").

## Patch manifest and file naming

- Patch manifest URL: `{setup_file_url}/{latest_hash}-{current_hash}`
  - saved as `patchdata/patch_<latest8>-<current8>.json`
  - e.g. `patchdata/patch_d8d486e0-9ae5648c.json`
- `.nxdelta` chunk URL:
  `{setup_file_url}/{b64path}.{id}.{chunk_sha1}.{file_sha1}.nxdelta`
  - e.g. `…/R2FtZUFzc2VtYmx5LmRsbA==.0.af3dad13….4a0dc61d….nxdelta`
- Each `.nxdelta` chunk is zlib-compressed. After decompression the chunk's
  SHA-1 must match the chunk hash from the manifest.
- All decompressed chunks of a file are concatenated in numeric chunk order
  into `patchdata/patches/<decoded_path>.nxdlpatch` (the base64 path decoded,
  e.g. `patchdata/patches/Maplestory_Classic.exe.nxdlpatch`).

## `.nxdlpatch` opcode stream

The patch is a sequential opcode stream. The decoder keeps:

- a cursor into the **old file** (advanced by `0x04` and the seek ops),
- a sequential cursor into the **output file** (always advanced by writes).

| Opcode | Arguments | Meaning |
| ------ | --------- | ------- |
| `0x00` | — | End of patch. The stream may also simply end at EOF without a terminator. |
| `0x04` | `u8` (unused), `u16 count` | Copy `count` bytes from the old file at its **current position**. |
| `0x10` | `u16 offset`, `u8 count` | Seek the old file to `offset`, copy `count` bytes. |
| `0x14` | `u16 offset`, `u16 count` | Seek the old file to `offset`, copy `count` bytes. |
| `0x20` | `u32 offset`, `u8 count` | Seek the old file to `offset`, copy `count` bytes. |
| `0x24` | `u32 offset`, `u16 count` | Seek the old file to `offset`, copy `count` bytes. |
| `0x40` | `u8 count` | Copy `count` literal bytes from the patch stream. |
| `0x44` | `u16 count` | Copy `count` literal bytes from the patch stream. |

All integers are little-endian. Unknown opcodes must abort the patch.

### Reference decoder (C#)

```csharp
while (patch_br.BaseStream.Position < patch_br.BaseStream.Length)
{
    byte opcode = patch_br.ReadByte();
    if (opcode == 0) break;
    switch (opcode)
    {
        case 0x04: /* u8 + u16 count */ from → to (current positions); break;
        case 0x10: /* u16 offset + u8 count */  from.Seek(off); from → to; break;
        case 0x14: /* u16 offset + u16 count */ from.Seek(off); from → to; break;
        case 0x20: /* u32 offset + u8 count */  from.Seek(off); from → to; break;
        case 0x24: /* u32 offset + u16 count */ from.Seek(off); from → to; break;
        case 0x40: /* u8 count */  patch → to; break;
        case 0x44: /* u16 count */ patch → to; break;
        default: throw;
    }
}
```

## Apply workflow

1. Read the current manifest hash from
   `<target_dir>/<stripped_appid>.manifest.hash`.
2. Resolve the target manifest hash: an explicit hash, or `latest` (game-info
   API).
3. Download the patch manifest JSON.
4. Download, decompress, verify, and concatenate the `.nxdelta` chunks of
   each patched file into `patchdata/patches/<decoded_path>.nxdlpatch`.
5. Apply each patch file:
   - write the patched result to `patchdata/applied/<path>` first,
   - then move it over the original file (`<target_dir>/<path>`),
   - delete the `.nxdlpatch` file after success.
6. Update `<stripped_appid>.manifest.hash` to the new manifest hash.

## Validation notes

- PE `CheckSum` field location: file offset `e_lfanew + 4 + 20 + 64`
  (PE signature + COFF header + optional-header offset 64).
- Checksum algorithm (Win32 `MapFileAndCheckSum`):
  sum all `u16` words, folding `(sum & 0xffff) + (sum >> 16)` after **every**
  addition; add the last byte if the length is odd; one final fold; then add
  the file length. The `CheckSum` field itself is excluded (treated as zero).
- A downloaded patch may target a build that differs slightly from a locally
  obtained `.new` sample (e.g. embedded build-ID strings differ, which also
  changes the PE checksum). Validate a decoded patch by PE-checksum
  self-consistency rather than byte-equality with a sample file.

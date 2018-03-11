---
title: "VirtualBox Live State File Format"
date: 2018-01-29T00:10:03-05:00
draft: false
toc: true
comments: true
categories:
- Forensics
tags:
- VirtualBox
---

In [Mounting Live Snapshots of Encrypted VMs in VirtualBox]({{< relref "2018-01-23-mounting-live-snapshot-virtualbox.markdown" >}} "Mounting Live Snapshots of Encrypted VMs in VirtualBox") we mounted a live snapshot and logged into the machine. We also got a sneak peek of what kind of information we can extract from the live snapshot (`sav` file).

In this post I will talk about parts of the live state file format and show some data that can be extracted from these files. The format is not formally documented but we have access to commented source.

To make it easier, I have uploaded the live state from our previous MysteryVM separately. You can download it from [Google Drive][gdrive-livestate] (45 MB).

<!--more-->

# Dive into sav
According to [this thread](https://www.virtualbox.org/pipermail/vbox-dev/2012-October/010986.html), "
A .sav file is created using the SSM (saved state manager) code. You find the API in include/VBox/vmm/ssm.h and src/VBox/VMM/VMMR3/SSM.cpp."

These are the relevant files:

- [https://www.virtualbox.org/svn/vbox/trunk/include/VBox/vmm/ssm.h][ssm-h]
- [https://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/VMMR3/SSM.cpp][ssm-cpp]

## Sav File Header - SSMFILHDR
First 64 bytes are the file header.

```
00000000  7f 56 69 72 74 75 61 6c 42 6f 78 20 53 61 76 65  |.VirtualBox Save|
00000010  64 53 74 61 74 65 20 56 32 2e 30 0a 00 00 00 00  |dState V2.0.....|
00000020  05 00 01 00 1c 00 00 00 d0 cc 01 00 40 08 08 00  |........ÐÌ..@...|
00000030  2a 00 00 00 01 00 00 00 00 10 00 00 08 df 3b 9e  |*............ß;.|
```

Inside [SSM.cpp][ssm-cpp] search for `struct SSMFILEHDR`:

{{< codecaption title="SSMFILEHDR - SSM.cpp" lang="cpp" >}}
typedef struct SSMFILEHDR
{
    /** Magic string which identifies this file as a version of VBox saved state
     *  file format (SSMFILEHDR_MAGIC_V2_0). */
    char            szMagic[32];
    /** The major version number. */
    uint16_t        u16VerMajor;
    /** The minor version number. */
    uint16_t        u16VerMinor;
    /** The build number. */
    uint32_t        u32VerBuild;
    /** The SVN revision. */
    uint32_t        u32SvnRev;
    /** 32 or 64 depending on the host. */
    uint8_t         cHostBits;
    /** The size of RTGCPHYS. */
    uint8_t         cbGCPhys;
    /** The size of RTGCPTR. */
    uint8_t         cbGCPtr;
    /** Reserved header space - must be zero. */
    uint8_t         u8Reserved;
    /** The number of units that (may) have stored data in the file. */
    uint32_t        cUnits;
    /** Flags, see SSMFILEHDR_FLAGS_XXX.  */
    uint32_t        fFlags;
    /** The maximum size of decompressed data. */
    uint32_t        cbMaxDecompr;
    /** The checksum of this header.
     * This field is set to zero when calculating the checksum. */
    uint32_t        u32CRC;
} SSMFILEHDR;
{{< /codecaption >}}

First 32 bytes contain the `magic string`.

{{< codecaption title="SSMFILEHDR_MAGIC_V2_0" lang="cpp" >}}
/** Saved state file v2.0 magic. */
#define SSMFILEHDR_MAGIC_V2_0  "\177VirtualBox SavedState V2.0\n\0\0\0"
{{< /codecaption >}}

`\177` is octal (base 8) or `0x7F`.

```
00000020  05 00 01 00 1c 00 00 00 d0 cc 01 00 40 08 08 00  |........ÐÌ..@...|
```

Then the rest (in little-endian):

- `05 00`: Major version number == `5`.
- `00 10`: Minor version number == `1`.
- `1c 00 00 00`: Build number == `28`.
- `d0 cc 01 00`: SVN revision == `117968`.
- `40`: Host bits == `64` (32 bit or 64 bit host).
- `08`: Size of RTGCPHYS (Guest physical memory address) == `08`.
- `08`: Size of RTGCPTR (Guest context pointer) == `08`. I have no idea what this does.
- `00`: Reserved header space - must be zero.

Thanks to the reserved header space, these fields start at a new line:

```
00000030  2a 00 00 00 01 00 00 00 00 10 00 00 08 df 3b 9e  |*............ß;.|
```
- `2a 00 00 00`: Number of data units in the file == `42`.
- `01 00 00 00`: Flags, discussed below. `01` == it's a live save state file.
- `00 10 00 00`: Maximum size of decompressed data == `4096`.
- `08 df 3b 9e`: CRC-32 checksum of the header. Set to zero when calculating the checksum.

You can use the following code snippet to calculate CRC-32 in Go (remember to zero-out the last four bytes first):

{{< codecaption title="Calculate CRC-32" lang="go" >}}
package main

import (
    "encoding/hex"
    "fmt"
    "hash/crc32"
)

var str1 = "7F5669727475616C426F7820536176656453746174652056322E300A00000000
            050001001C000000D0CC0100400808002A000000010000000010000000000000"

func main() {
    bytes1, err := hex.DecodeString(str1)
    if err != nil {
        panic(err)
    }
    fmt.Printf("%x", crc32.ChecksumIEEE(bytes1))
}

// Returns: 9e3bdf08
{{< /codecaption >}}


Try it at [play.golang.org][crc32-playground].

For some reason CyberChef does not show the correct CRC-32 checksum while other online calculators do. Some info might be lost when convert hex bytes to chars and calculating the checksum.

### Flags
In short, flag is `01` if it's' a live save state (which was in our case) and `00` if the stream is checksummed up to the footer (not sure what this flag value is used for).

Flags are defined as follows:

{{< codecaption title="SSMFILEHDR::fFlags - SSM.cpp" lang="cpp" >}}
/** @name SSMFILEHDR::fFlags
 * @{ */
/** The stream is checksummed up to the footer using CRC-32. */
#define SSMFILEHDR_FLAGS_STREAM_CRC32           RT_BIT_32(0)
/** Indicates that the file was produced by a live save. */
#define SSMFILEHDR_FLAGS_STREAM_LIVE_SAVE       RT_BIT_32(1)
/** @} */
{{< /codecaption >}}

## Saved State Units
After the header we can see a number of saved state units that conveniently start with the text `Unit`.

Search for `typedef struct SSMUNIT` in [SSMInternal.h][SSMinternal-h] for more info.

We're going to look at the SSM unit, but all units have the same structure.

### SSM Data Unit
First data unit after the file header is the "Saved State" unit or SSM.

#### SSM Unit Header - SSMFILEUNITHDRV2
Each unit has its own header that is defined as follows:

{{< codecaption title="SSMFILEUNITHDRV2 - SSM.cpp" lang="cpp" >}}
typedef struct SSMFILEUNITHDRV2
{
    /** Magic (SSMFILEUNITHDR_MAGIC or SSMFILEUNITHDR_END). */
    char            szMagic[8];
    /** The offset in the saved state stream of the start of this unit.
     * This is mainly intended for sanity checking. */
    uint64_t        offStream;
    /** The CRC-in-progress value this unit starts at. */
    uint32_t        u32CurStreamCRC;
    /** The checksum of this structure, including the whole name.
     * Calculated with this field set to zero.  */
    uint32_t        u32CRC;
    /** Data version. */
    uint32_t        u32Version;
    /** Instance number. */
    uint32_t        u32Instance;
    /** Data pass number. */
    uint32_t        u32Pass;
    /** Flags reserved for future extensions. Must be zero. */
    uint32_t        fFlags;
    /** Size of the data unit name including the terminator. (bytes) */
    uint32_t        cbName;
    /** Data unit name, variable size. */
    char            szName[SSM_MAX_NAME_SIZE];
} SSMFILEUNITHDRV2;
{{< /codecaption >}}

THE SSM unit in our file is:

```
00000040  0a 55 6e 69 74 0a 00 00 40 00 00 00 00 00 00 00  |.Unit...@.......|
00000050  91 d4 5f f6 13 12 1d eb 01 00 00 00 00 00 00 00  |.Ô_ö...ë........|
00000060  ff ff ff ff 00 00 00 00 04 00 00 00 53 53 4d 00  |ÿÿÿÿ........SSM.|

00000070  92 39 0a 00 00 00 42 75 69 6c 64 20 54 79 70 65  |.9....Build Type|
00000080  07 00 00 00 72 65 6c 65 61 73 65 07 00 00 00 48  |....release....H|
00000090  6f 73 74 20 4f 53 09 00 00 00 77 69 6e 2e 61 6d  |ost OS....win.am|
000000a0  64 36 34 00 00 00 00 00 00 00 00                 |d64........|
```

First 8 bytes contain the data unit magic header. It can have two values:

{{< codecaption title="Magics - SSM.cpp" lang="cpp" >}}
/** Data unit magic. */
#define SSMFILEUNITHDR_MAGIC    "\nUnit\n\0"
/** Data end marker magic. */
#define SSMFILEUNITHDR_END      "\nTheEnd"
{{< /codecaption >}}

`TheEnd` appears in the the block after all data units.

In this data unit we have `0a 55 6e 69 74 0a 00 00` or `\nUnit\n\0`.

Starting from offset `0x40` we have:

- `40 00 00 00`: Offset of this unit in the stream. For this unit it's `0x40`. In other words, if we go this offset in the sav file, we will see this data unit.
- `00 00 00 00`: The CRC-in-progress value this unit starts at. No idea what this is. It could be the default value of the CRC bytes when we are creating the CRC checksum (see above). At has been zero for this data unit in all live states I have seen.
- `91 d4 5f f6`: Checksum of the data unit with these bytes set to zero.
- `13 12 1d eb`: Data version == `eb 1d 12 13`. (?)
- `01 00 00 00`: Instance number == `01`. (?)
- `00 00 00 00`: Data pass number == `00`. (?)
- `ff ff ff ff`: **These 4 bytes do not appear in the spec.** Could be alignment for the data unit header? These appear in every live state.
- `00 00 00 00`: Flags reserved for future extensions. Must be zero.
- `04 00 00 00`: Size of null-terminated data unit name in bytes, `4` in this data unit. In other words, read this many bytes to get the data unit name with the null terminator.
- `53 53 4d 00`: Data unit name and null terminator, `SMM`.

#### SSM Unit Data
Going back up the [SSM.cpp][ssm-cpp] file we can see the specifications for the data in this unit:

```
00000070  92 39 0a 00 00 00 42 75 69 6c 64 20 54 79 70 65  |.9....Build Type|
00000080  07 00 00 00 72 65 6c 65 61 73 65 07 00 00 00 48  |....release....H|
00000090  6f 73 74 20 4f 53 09 00 00 00 77 69 6e 2e 61 6d  |ost OS....win.am|
000000a0  64 36 34 00 00 00 00 00 00 00 00                 |d64........|
```

"The first byte in the record header indicates the type and flags." We have `0x92` or `1001 0010`:

- bits 0..3 - Record type `0010`: type = Raw data record.
- bit 4: `1` if important and `0` if it can be skipped. This is an important data unit.
- bits 5, 6: Must be `0`.
- bit 7: Always `1`.

"Record header byte 2 (optionally thru 7) is the size of the following data encoded in UTF-8 style." We have `0x39` or `57` decimal. So we will read 57 bytes.

This part is easy. Read a little-endian uint32, that's field length. Then read that many bytes to get the field. This is a typical Pascal style string (as seen in ASN.1 format) which do not have null/string terminators.

- `0a 00 00 00 - 42 75 69 6c 64 20 54 79 70 65`: 10 bytes - `Build Type`.
- `07 00 00 00 - 72 65 6c 65 61 73 65`: 7 bytes - `release`.
- `07 00 00 00 - 48 6f 73 74 20 4f 53`: 7 bytes - `Host OS`.
- `09 00 00 00 - 77 69 6e 2e 61 6d 64 36 34`: 9 bytes - `win.amd64`.
- `00 00 00 00 - 00 00 00 00`: 0 bytes - empty (?).

### End Data Unit
This is the last data unit. It starts with the magic header `SSMFILEUNITHDR_END`:

{{< codecaption title="SSMFILEUNITHDR_END - SSM.cpp" lang="cpp" >}}
/** Data end marker magic. */
#define SSMFILEUNITHDR_END                      "\nTheEnd"
{{< /codecaption >}}

We can see it at offset `0x4C7A712`:

{{< imgcap title="End data unit" src="/images/2018/vbox2/01-end-unit.png" >}}

```
00000000  0a 54 68 65 45 6e 64 00 12 a7 c7 04 00 00 00 00  |.TheEnd..§Ç.....|
00000010  94 e5 7d 35 47 2b 45 32 00 00 00 00 00 00 00 00  |.å}5G+E2........|
00000020  ff ff ff ff 00 00 00 00 00 00 00 00              |ÿÿÿÿ........|
```

End data unit does not have any data, it's just header and does not have a name. Using the `SSMFILEUNITHDRV2` struct we can dissect the data here:

- `0a 54 68 65 45 6e 64 00`: Header `"\nTheEnd"`.
- `12 a7 c7 04`: Offset of this unit == `04 c7 a7 12`.
- `00 00 00 00`: CRC-in-progress.
- `94 e5 7d 35`: Checksum of the data unit.
- `47 2b 45 32`: Data version. (?)
- `00 00 00 00`: Instance number.
- `00 00 00 00`: Data pass number.
- `ff ff ff ff`: Not in spec, but appear in every data unit.
- `00 00 00 00`: Flags reserved for future extensions. Must be zero.
- `00 00 00 00`: Size of data unit name in bytes. Zero here.

## Directory
In our file, directory is just right after the end unit.

{{< imgcap title="End data unit" src="/images/2018/vbox2/02-dir.png" >}}

It has a header followed by some directory entries.

### Directory Header - SSMFILEDIR

Inside [SSM.cpp][ssm-cpp] search for `SSMFILEDIR`:

{{< codecaption title="SSMFILEDIR - SSM.cpp" lang="cpp" >}}
/**
 * Directory for the data units from the final pass.
 *
 * This is used to speed up SSMR3Seek (it would have to decompress and parse the
 * whole stream otherwise).
 */
typedef struct SSMFILEDIR
{
    /** Magic string (SSMFILEDIR_MAGIC). */
    char            szMagic[8];
    /** The CRC-32 for the whole directory.
     * Calculated with this field set to zero. */
    uint32_t        u32CRC;
    /** The number of directory entries. */
    uint32_t        cEntries;
    /** The directory entries (variable size). */
    SSMFILEDIRENTRY aEntries[1];
} SSMFILEDIR;

/** The directory magic. */
#define SSMFILEDIR_MAGIC                        "\nDir\n\0\0"
{{< /codecaption >}}

```
00000000  0a 44 69 72 0a 00 00 00 ef 86 a6 b5 22 00 00 00  |.Dir....ï.¦µ"...|
```

- `0a 44 69 72 0a 00 00 00`: Magic header.
- `ef 86 a6 b5`: CRC-32 of the whole directory.
- `22 00 00 00`: Number of directories `0x22` == `34` decimal.

Then we have 34 directory (each directory is 16 bytes) of type `SSMFILEDIRENTRY`.

## Directories - SSMFILEDIRENTRY
Directories have a simple structure.

{{< codecaption title="SSMFILEDIRENTRY - SSM.cpp" lang="cpp" >}}
/**
 * Directory entry.
 */
typedef struct SSMFILEDIRENTRY
{
    /** The offset of the data unit. */
    uint64_t        off;
    /** The instance number. */
    uint32_t        u32Instance;
    /** The CRC-32 of the name excluding the terminator. (lazy bird) */
    uint32_t        u32NameCRC;
} SSMFILEDIRENTRY;
{{< /codecaption >}}

We will look at the first one:

```
00000010  40 00 00 00 00 00 00 00 00 00 00 00 41 7a 40 08  |@...........Az@.|
```

- `40 00 00 00 00 00 00 00`: Data unit offset. We have already seen this data unit. This is the SSM unit.
- `00 00 00 00`: Instance number == `0x00`.
- `41 7a 40 08`: CRC-32 of the name excluding the terminator.

## File Footer - SSMFILEFTR
Finally we have the file footer.

{{< codecaption title="SSMFILEFTR_MAGIC and SSMFILEFTR - SSM.cpp" lang="cpp" >}}
/** Saved state file v2.0 magic. */
#define SSMFILEFTR_MAGIC                        "\nFooter"

/**
 * Footer structure
 */
typedef struct SSMFILEFTR
{
    /** Magic string (SSMFILEFTR_MAGIC). */
    char            szMagic[8];
    /** The offset of this record in the stream. */
    uint64_t        offStream;
    /** The CRC for the stream.
     * This is set to zero if SSMFILEHDR_FLAGS_STREAM_CRC32 is clear. */
    uint32_t        u32StreamCRC;
    /** Number directory entries. */
    uint32_t        cDirEntries;
    /** Reserved footer space - must be zero. */
    uint32_t        u32Reserved;
    /** The CRC-32 for this structure.
     * Calculated with this field set to zero. */
    uint32_t        u32CRC;
} SSMFILEFTR;
{{< /codecaption >}}

Which is:

```
00000000  0a 46 6f 6f 74 65 72 00 6e a9 c7 04 00 00 00 00  |.Footer.n©Ç.....|
00000010  c7 2f 92 29 22 00 00 00 00 00 00 00 bc d2 96 8d  |Ç/.)".......¼Ò..|
```

Based on the struct we can dissect it:

- `0a 46 6f 6f 74 65 72 00`: `SSMFILEFTR_MAGIC` == `\nFooter`.
- `6e a9 c7 04`: Offset of this record in the stream == `04 c7 a9 6e`.
- `00 00 00 00`: CRC-32 of the stream. It's set to zero.
- `c7 2f 92 29`: **This is not in the struct.**
- `22 00 00 00`: Number of directory entries == `34` decimal.
- `00 00 00 00`: Reserved, must be zero.
- `bc d2 96 8d`: CRC-32 for this structure. Set to zero during calculation.

There's one extra `uint32` in the footer. I do not know what `29 92 2f c7` is.

# Conclusion
We learned how to extract some information from VBox sav files with a practical example. Although the product is opensource, the format does not have public documentation.

<!-- Links -->

[gdrive-livestate]: https://drive.google.com/file/d/1WdlcHsQattvFs8Wu9RdFC5UOaSxqhk0d/view?usp=sharing
[ssm-h]: https://www.virtualbox.org/svn/vbox/trunk/include/VBox/vmm/ssm.h
[ssm-cpp]: https://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/VMMR3/SSM.cpp
[crc32-playground]: https://play.golang.org/p/NHF3WBkUmzN
[SSMinternal-h]: https://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/include/SSMInternal.h


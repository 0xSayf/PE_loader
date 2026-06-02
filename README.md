# PE Loader (32-bit)

A from-scratch Windows PE (Portable Executable) loader written in C. It reads a 32-bit PE file from disk, maps it into memory exactly as the Windows loader would, resolves all imports, applies base relocations, sets correct memory permissions per section, and transfers execution to the entry point.

---

## Overview

This project implements the core steps of the Windows PE loading process manually:

1. Read the raw PE file from disk into a buffer
2. Detect architecture from the Optional Header magic value
3. Allocate executable memory and map headers + sections
4. Resolve the Import Address Table (IAT) using `LoadLibraryA` + `GetProcAddress`
5. Apply base relocations if the image didn't load at its preferred address
6. Set correct memory protections per section (RX, RW, RWX, RO)
7. Jump to the entry point

---

## Files

| File | Description |
|---|---|
| `main.c` | Entry point — file I/O, architecture detection, dispatch to loader |
| `loader.c` | `ft_load_32` — full 32-bit PE mapping, IAT resolution, relocation, execution |
| `include.h` | Shared headers and declarations |

---

## How It Works

### Step 1 — Architecture Detection (`ft_checking_arch`)

Reads `e_lfanew` at offset `0x3C` in the DOS header, then reads the Optional Header magic at `e_lfanew + 24`:

| Magic | Architecture |
|---|---|
| `0x10B` | PE32 (32-bit) → `ft_load_32` |
| `0x20B` | PE32+ (64-bit) → not yet implemented |

---

### Step 2 — Memory Allocation

```
VirtualAlloc(NULL, size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
```

Allocates a region large enough for the full mapped image (`SizeOfImage` from the Optional Header at `e_lfanew + 0x50`).

---

### Step 3 — Mapping Headers and Sections

- The DOS header through the end of all NT headers is copied as-is (`size_of_headers` bytes)
- Each section is then mapped from its raw file offset (`PointerToRawData`) to its virtual address (`VirtualAddress`), using the section table entries starting at `e_lfanew + 0x18 + SizeOfOptionalHeader`

---

### Step 4 — IAT Resolution

Walks the `IMAGE_IMPORT_DESCRIPTOR` array (located via the import directory RVA at `e_lfanew + 0x80`):

- For each imported DLL, calls `LoadLibraryA`
- Walks the Import Lookup Table (ILT) in parallel with the IAT:
  - **By name:** reads the `IMAGE_IMPORT_BY_NAME` hint/name entry, calls `GetProcAddress`
  - **By ordinal:** extracts the ordinal from the high bit of the thunk, calls `GetProcAddress` with ordinal cast
- Writes resolved function addresses into the IAT (`IAT32[j].u1.Function`)

---

### Step 5 — Base Relocations

If the image did not load at its preferred base (`ImageBase` at `e_lfanew + 0x34`), the delta is computed and applied to all `IMAGE_REL_BASED_HIGHLOW` entries in the `.reloc` section (relocation directory RVA at `e_lfanew + 0xA0`).

Each relocation block (`IMAGE_BASE_RELOCATION`) encodes a page RVA and a list of 16-bit entries, where the top 4 bits are the type and the bottom 12 bits are the page-relative offset.

---

### Step 6 — Memory Protections

After loading, memory protections are tightened to match section characteristics:

| Characteristics | Protection |
|---|---|
| Execute + Write | `PAGE_EXECUTE_READWRITE` |
| Execute only | `PAGE_EXECUTE_READ` |
| Write only | `PAGE_READWRITE` |
| Read only | `PAGE_READONLY` |

Headers are set to `PAGE_READONLY` (`0x02`).

---

### Step 7 — Entry Point Execution

```c
void (*entry)() = (void (*)())(image_base + entrypoint);
entry();
```

Casts the entry point RVA (at `e_lfanew + 0x28`) + image base to a function pointer and calls it.

---

## PE Offset Reference

| Field | Offset from `e_lfanew` |
|---|---|
| Number of sections | `+0x06` |
| Entry point RVA | `+0x28` |
| SizeOfImage | `+0x50` |
| SizeOfHeaders | `+0x54` |
| SizeOfOptionalHeader | `+0x14` |
| ImageBase (preferred) | `+0x34` |
| Import directory RVA | `+0x80` |
| Relocation directory RVA | `+0xA0` |
| First section header | `+0x18 + SizeOfOptionalHeader` |

---

## Build

### Linux (cross-compile)

```bash
x86_64-w64-mingw32-gcc main.c loader.c -o pe_loader.exe -lkernel32
```

### Windows (MinGW)

```bash
gcc main.c loader.c -o pe_loader.exe
```

### Windows (MSVC)

```bash
cl main.c loader.c /Fe:pe_loader.exe
```

---

## Usage

```
pe_loader.exe <path_to_32bit_pe>
```

## Current Limitations

- Only PE32 (32-bit) is supported; the PE32+ (64-bit) path is not yet implemented
- No TLS callback handling
- No bound imports support
- No delay-load import resolution
- The loaded image runs in the same process as the loader

---

## Requirements

- **Target:** Windows x86 or x86-64 (running 32-bit PE files via WoW64)
- **Build:** MinGW-w64 or MSVC
- **Dependencies:** `kernel32.dll` (`VirtualAlloc`, `VirtualProtect`, `LoadLibraryA`, `GetProcAddress`)

---

## Disclaimer

This project is intended for **educational purposes**, **malware analysis research**, and **authorized security testing** only. Use only on systems and files you own or have explicit permission to analyze.

      

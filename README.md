<p align="center">
  <img src="assets/pawnd_badge.svg" alt="pawnd logo" width="400"/>
</p>

# pawnd

🐾 A collection of **GEF/GDB add-ons** for exploit development and memory triage.

- `whereis` — tell where an address lives (stack / thread stack / heap / shared lib / vdso / anon / etc.) and show mapping details.
- `badchars` — generate a clean 0x00–0xFF byte set and compare memory to find the first “badchar” quickly.

---

## Contents

```
pawnd/
├─ README.md
├─ LICENSE
├─ gef.d/
│  ├─ whereis.py
│  └─ badchars.py
└─ examples/
   ├─ whereis_demo.md
   └─ badchars_demo.md
```

---

## Requirements

- Linux (tested on common distros) with `/proc/<pid>/maps`
- GDB with Python support (GDB ≥ 8 recommended)
- [GEF](https://github.com/hugsy/gef) installed/loaded
- Python 3.7+

`whereis` works with **x86 (32-bit) and x86-64** inferiors.

---

## Install

Clone and point **pawnd** at the plugins directory (autoload), or symlink them into `~/.gdb/gef.d`:

```bash
git clone https://github.com/kryptohaker/pawnd.git
cd pawnd

# Option A: tell GEF to load from this folder
gef config gef.extra_plugins_dir "$PWD/gef.d"
# (GEF persists this; restart GDB, or run `gef reload`)

# Option B: symlink into your standard plugin dir
mkdir -p ~/.gdb/gef.d
ln -sf "$PWD/gef.d/"*.py ~/.gdb/gef.d/
```

Manual loading also works:

```gdb
(gdb) source /path/to/pawnd/gef.d/whereis.py
(gdb) source /path/to/pawnd/gef.d/badchars.py
```

Quickstart one-liner:

```bash
git clone https://github.com/kryptohaker/pawnd.git && gef config gef.extra_plugins_dir "$PWD/pawnd/gef.d"
```

---

## Usage

### `whereis` — classify an address / find its mapping

```
whereis <address-or-expression>
```

Accepts:
- Hex (e.g., `0xdeadbeef`)
- Registers: `$sp` (portable), `$rsp`, `$esp`, `$pc`, `$eip`, etc.
- Expressions: `&global_var`, `buf+0x20`, `*(void**)($sp)`

Examples:

```gdb
(gdb) whereis $sp     # portable across x86/x86-64 ($esp/$rsp)
(gdb) whereis $eip
(gdb) whereis 0xf7ffcfec
(gdb) whereis &some_global
```

Sample output:

```
gef➤  whereis 0xf7ffcfec
============================================================
[?] Address: 0xf7ffcfec
[+] Region: SHARED LIB
    Range : 0xf7ffb000 - 0xf7ffd000  (size 0x2000)
    Perms : r--p    Offset: 0x33000    Dev: 08:01    Inode: 4995761
    Path  : /usr/lib32/ld-linux.so.2
    +0x1fec from region start
============================================================
```

What it does:
- Parses `/proc/<pid>/maps` (live) or falls back to `info proc mappings`.
- Classifies: **HEAP**, **STACK** (and per-thread `STACK (thread)`), **SHARED LIB**, **EXECUTABLE / MAPPED FILE**, **VDSO**, **VVAR**, **VSYSCALL**, **ANON**, **(deleted) files**.
- Prints region bounds, perms, file/offset, and distance from region start.
- Tries `info symbol` for a quick symbol hint when available.

**x86 note:** GPRs like `$ebx` can be sign-extended by GDB when read as integers. `whereis` masks values to the current pointer width, so `whereis $ebx` resolves correctly.

---

### `badchars` — generate & compare

```
badchars --generate [-b \x00\x0a]
badchars --compare --addr <hex_address> [-b \x00\x0a\x20]
```

- `--generate` writes `badchars.bin` containing bytes `0x00..0xFF` excluding any provided skips (`-b`).
- `--compare` reads memory at `--addr` for `len(badchars.bin)` bytes and shows the first mismatch, stopping early so you quickly learn the **next** bad char. Provide already-known bad chars with `-b` to skip them.

Examples:

```gdb
(gdb) badchars --generate -b \x00\x0a

[+] badchars.bin generated with 0x00–0xFF (excluding skips)
[!] Skipped: ['0x00', '0x0a']
[+] Python format for copy-paste:
badchars = b"\x01\x02\x03 ..."

(gdb) badchars --compare --addr 0xffffd0a0 -b \x00\x0a

--------------------
File:   0x01    0x02    0x03    0x04    0x05    0x06    0x07    0x08
Memory: 0x01    0x02    0x03    ----    ----    ----    ----    ----
--------------------
[!] Badchars detected: ['0x00', '0x0a', '0x04']
[+] Easy copy-paste format: "\x00\x0a\x04"
```

Tips:
- Usually you inject the generated pattern into the vulnerable buffer and then `--compare` at the buffer address.
- For larger overreads, keep `badchars.bin` intact; the tool stops at the first new bad byte to speed iteration.

---

## Design notes

- **Arch-agnostic:** uses GDB’s `$sp` and masks addresses to the current pointer width.
- **Thread stacks:** `[stack:<tid>]` regions are labeled **STACK (thread)**.
- **Remote/core debugging:** if `/proc/<pid>/maps` isn’t available, the tool parses `info proc mappings` as a fallback.
- **Symbol hints:** attempts `info symbol <addr>` and prints any match.

---

## Troubleshooting

- **“Address is not in any known user-space mapping”**  
  → The address isn’t mapped, points to kernel space on 32-bit, or your inferior isn’t running/attached.
- **“No inferior selected.”**  
  → Start/attach first: `run`, `attach <pid>`, or `target remote`.
- **Negative hex like `0x-...` from registers**  
  → Fixed: addresses are masked to pointer size. Update the script if you still see this.
- **Remote sessions with limited `info proc mappings`**  
  → Some stubs don’t expose mappings. Attach locally, or use platform-specific tools to inspect maps.

---

## Roadmap

- `whereis --near` to list neighboring mappings around an address
- JSON output mode for tooling
- Optional colorized output

---

## Contributing

PRs and issues welcome! Please keep features small and focused. For new commands, follow the same pattern: a single `gdb.Command` subclass per file under `gef.d/`.

1. Fork and create a feature branch  
2. Add tests/examples where it helps  
3. Open a PR with a clear before/after  

---

## License

MIT — see [LICENSE](./LICENSE).

## Attribution

pawnd is developed and maintained by [kryptohaker](https://github.com/kryptohaker) and [Hardenwall](https://hardenwall.com) 🛡️


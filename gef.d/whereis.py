#!/usr/bin/env python3
# whereis.py — GDB command to classify an address by memory region.
#
# Part of the pawnd toolkit: https://github.com/kryptohaker/pawnd
#
# Usage:
#   (gdb) source /path/to/pawnd/gef.d/whereis.py
#   (gdb) whereis 0xdeadbeef
#   (gdb) whereis $rsp
#   (gdb) whereis &some_global

import gdb
import os
import re
from collections import namedtuple

Region = namedtuple("Region", "start end perms offset dev inode path")

def pawnd_banner(tool: str, desc: str):
    print("[pawnd] ===============================")
    print(f"[pawnd]   {tool} — {desc}")
    print("[pawnd]   GEF/GDB add-ons for pwn dev")
    print(f'[pawnd]   Type "help {tool}" for usage')
    print("[pawnd] ===============================")

def _addr_bits():
    # Get pointer width for current arch (32 or 64)
    try:
        return gdb.lookup_type('void').pointer().sizeof * 8
    except Exception:
        return 64

def _addr_mask():
    return (1 << _addr_bits()) - 1

def _to_addr(v) -> int:
    # Convert to int and mask to pointer width
    return int(v) & _addr_mask()

def _hex(n: int) -> str:
    return "0x%x" % (_to_addr(n))

def _parse_addr(expr: str) -> int:
    expr = expr.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]+", expr):
        return _to_addr(int(expr, 16))

    val = gdb.parse_and_eval(expr)
    # Try to get address of variables first
    try:
        return _to_addr(val.address)
    except Exception:
        pass
    # Otherwise use the value directly (for registers, etc)
    return _to_addr(val)

def _read_proc_maps(pid: int):
    """Parse /proc/<pid>/maps"""
    maps_path = f"/proc/{pid}/maps"
    regions = []
    with open(maps_path, "r") as f:
        for line in f:
            # Format: 00400000-00452000 r-xp 00000000 08:01 131127  /usr/bin/cat
            parts = line.rstrip("\n").split(None, 5)
            if len(parts) < 5:
                continue
            addr_range, perms, offset, dev, inode = parts[:5]
            path = parts[5] if len(parts) == 6 else ""
            start_s, end_s = addr_range.split("-")
            regions.append(Region(
                start=int(start_s, 16),
                end=int(end_s, 16),
                perms=perms,
                offset=int(offset, 16),
                dev=dev,
                inode=int(inode),
                path=path if path else ""
            ))
    return regions

def _fallback_info_proc_mappings():
    """Parse 'info proc mappings' when /proc isn't available"""
    out = gdb.execute("info proc mappings", to_string=True)
    regions = []
    # Expected format: 0x555555554000 0x555555575000 r-xp   21000  123:45  678901 /path
    pat = re.compile(
        r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+([rwxps\-]+)\s+([0-9a-fA-Fx]+)\s+([0-9:]+)\s+(\d+)\s*(.*)$"
    )
    for line in out.splitlines():
        m = pat.match(line)
        if not m:
            continue
        start_s, end_s, perms, offset_s, dev, inode_s, path = m.groups()
        regions.append(Region(
            start=int(start_s, 16),
            end=int(end_s, 16),
            perms=perms,
            offset=int(offset_s, 16) if offset_s.startswith("0x") else int(offset_s, 16 if re.match(r"^[0-9a-fA-F]+$", offset_s) else 10),
            dev=dev,
            inode=int(inode_s) if inode_s.isdigit() else 0,
            path=path.strip()
        ))
    return regions

def _classify(path: str) -> str:
    """Get human-readable label for mapping"""
    p = path or ""
    if "[heap]" in p:
        return "HEAP"
    if p.startswith("[stack"):
        return "STACK (thread)" if ":" in p else "STACK"
    if "[vdso]" in p:
        return "VDSO"
    if "[vvar]" in p:
        return "VVAR"
    if "[vsyscall]" in p:
        return "VSYSCALL"
    if p == "" or p.startswith("[anon"):
        return "ANON"
    if p.endswith(" (deleted)"):
        return "MMAP (deleted file)"
    if "/" in p:
        if p.endswith(".so") or ".so." in p:
            return "SHARED LIB"
        return "EXECUTABLE / MAPPED FILE"
    return "MAPPING"

def _symbol_info(addr: int) -> str:
    sym = gdb.execute(f"info symbol {_hex(addr)}", to_string=True).strip()
    return sym

def _sp_in_region(reg: Region) -> bool:
    try:
        sp = int(gdb.parse_and_eval("$sp"))
        return reg.start <= sp < reg.end
    except Exception:
        return False

class WhereIsCommand(gdb.Command):
    """whereis <addr-or-expr>
Show which memory mapping contains the address, with details.
Examples:
  whereis 0xdeadbeef
  whereis $rsp
  whereis &global_var
"""

    def __init__(self):
        super(WhereIsCommand, self).__init__("whereis", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        arg = arg.strip()
        if not arg:
            print(self.__doc__)
            return

        try:
            addr = _parse_addr(arg)
        except ValueError as e:
            print(f"[!] {e}")
            return

        inf = gdb.selected_inferior()
        if inf is None:
            print("[!] No inferior selected.")
            return

        regions = []
        # Try /proc maps first for live processes
        try:
            pid = inf.pid
            if pid:
                regions = _read_proc_maps(pid)
            else:
                regions = _fallback_info_proc_mappings()
        except Exception:
            regions = _fallback_info_proc_mappings()

        # Find the region containing our address
        hit = None
        for r in regions:
            if r.start <= addr < r.end:
                hit = r
                break

        print("=" * 60)
        print(f"[?] Address: {_hex(addr)}")
        if not hit:
            print("[!] Address is not in any known user-space mapping (unmapped or invalid).")
            print("=" * 60)
            return

        kind = _classify(hit.path)
        size = hit.end - hit.start
        delta = addr - hit.start

        print(f"[+] Region: {kind}")
        print(f"    Range : {_hex(hit.start)} - {_hex(hit.end)}  (size {_hex(size)})")
        print(f"    Perms : {hit.perms}    Offset: {_hex(hit.offset)}    Dev: {hit.dev}    Inode: {hit.inode}")
        print(f"    Path  : {hit.path if hit.path else '(anonymous)'}")
        print(f"    +{_hex(delta)} from region start")

        # Check if we're looking at stack and where $sp is
        if kind.startswith("STACK"):
            print(f"    Note  : current $sp is {'inside' if _sp_in_region(hit) else 'NOT inside'} this mapping")

        # Try to resolve symbols
        try:
            sym = _symbol_info(addr)
            if sym and "No symbol" not in sym:
                print(f"    Symbol: {sym}")
        except Exception:
            pass

        print("=" * 60)

WhereIsCommand()

pawnd_banner("whereis", "classify addresses by memory region")
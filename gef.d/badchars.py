#!/usr/bin/env python3
# badchars.py — GDB command to generate or compare badchars in memory
#
# Part of the pawnd toolkit: https://github.com/kryptohaker/pawnd
#
# Usage:
#   (gdb) source /path/to/pawnd/gef.d/badchars.py
#   (gdb) badchars --generate [-b \\x00\\x0a]
#   (gdb) badchars --compare --addr <address> [-b \\x00\\x20]
import gdb
import os

def pawnd_banner(tool: str, desc: str):
    print("[pawnd] ===============================")
    print(f"[pawnd]   {tool} — {desc}")
    print("[pawnd]   GEF/GDB add-ons for pwn dev")
    print(f'[pawnd]   Type "help {tool}" for usage')
    print("[pawnd] ===============================")


class BadcharsCommand(gdb.Command):
    """Generate or compare badchars in memory
Usage:
  badchars --generate [-b \\x00\\x0a]
  badchars --compare --addr <address> [-b \\x00\\x20]
"""

    def __init__(self):
        super(BadcharsCommand, self).__init__("badchars", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)

        if not args:
            print(self.__doc__)
            return

        # Generate badchars file
        if args[0] == "--generate":
            skip = []
            if "-b" in args:
                skip_str = args[args.index("-b")+1]
                skip = [int(skip_str[i+2:i+4], 16)
                        for i in range(0, len(skip_str), 4)]
            self.generate(skip)
            return

        # Compare memory with file
        elif args[0] == "--compare":
            if "--addr" not in args:
                print("[!] You must specify --addr <hex address>")
                return
            addr = int(args[args.index("--addr")+1], 16)

            known = []
            if "-b" in args:
                skip_str = args[args.index("-b")+1]
                known = [int(skip_str[i+2:i+4], 16)
                         for i in range(0, len(skip_str), 4)]

            self.compare(addr, known)
            return

        else:
            print(self.__doc__)

    def generate(self, skip_badchars):
        """Write badchars file with full byte range minus skips"""
        data = bytes(b for b in range(0, 256) if b not in skip_badchars)
        with open("badchars.bin", "wb") as f:
            f.write(data)

        print("[+] badchars.bin generated with 0x00–0xFF (excluding skips)")
        if skip_badchars:
            print("[!] Skipped:", ["0x%02x" % b for b in skip_badchars])

        python_str = ''.join('\\x%02x' % b for b in data)
        print("[+] Python format for copy-paste:")
        print('badchars = b"%s"' % python_str)

    def compare(self, addr, known_badchars=None):
        """Read memory and diff against badchars file"""
        if not os.path.exists("badchars.bin"):
            print("[!] badchars.bin not found. Run `badchars --generate` first.")
            return

        expected = open("badchars.bin", "rb").read()
        length = len(expected)

        mem = gdb.selected_inferior().read_memory(addr, length)
        mem_bytes = bytearray(mem)

        if known_badchars:
            print("[!] Known badchars (skipped from file):",
                  ["0x%02x" % b for b in known_badchars])

        print("-" * 20)
        first_missing = None

        for offset in range(0, length, 8):
            file_chunk = expected[offset:offset+8]
            mem_chunk = mem_bytes[offset:offset+8]

            # Show file bytes
            file_str = "    ".join("0x%02x" % b for b in file_chunk)
            print("File:   %s" % file_str)

            # Show memory bytes, mark mismatches with ----
            mem_str_parts = []
            for i in range(len(file_chunk)):
                f_b = file_chunk[i]
                m_b = mem_chunk[i] if i < len(mem_chunk) else None
                if m_b == f_b:
                    mem_str_parts.append("0x%02x" % m_b)
                else:
                    if first_missing is None:
                        first_missing = f_b
                    mem_str_parts.append("----")

            print("Memory: %s" % "    ".join(mem_str_parts))

            # Stop at first mismatch
            if first_missing is not None:
                break

        print("-" * 20)

        if first_missing is not None:
            all_badchars = (known_badchars or []) + [first_missing]
            unique_badchars = list(dict.fromkeys(all_badchars))  # dedup but keep order
            hex_list = ["0x%02x" % b for b in unique_badchars]
            print("[!] Badchars detected:", hex_list)
            print("[+] Easy copy-paste format: \"%s\"" % "".join("\\x%02x" % b for b in unique_badchars))
        else:
            print("[+] No new badchars detected.")

BadcharsCommand()

pawnd_banner("badchars", "generate or compare badchars in memory")

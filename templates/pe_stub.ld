/* pe_stub.ld — layout control for pe_stub_x64.c
 *
 * Produces a standard PE (NOT binary format — patcher.py extracts with pefile).
 *
 * .text  at RVA 0x1000  → flat-binary offset 0x000
 * .data  at RVA 0x11F0  → flat-binary offset 0x1F0
 *
 * Offsets in extracted flat binary:
 *   0x000 : ShimEntry code
 *   0x1F0 : stub_magic  = 0xCAFEBABEDEADBEEF
 *   0x1F8 : oep_rva     = 0  (patched by patcher.py)
 *   0x200 : shellcode appended by patcher.py
 *
 * C code: void *sc = (char *)&stub_magic + 0x10
 *   → at runtime: section_va + 0x1F0 + 0x10 = section_va + 0x200  ✓
 */

SECTIONS {
    . = 0x1000;
    .text   : { *(.text .text.*) }
    . = 0x11F0;
    .data   : { *(.data .data.* .rodata .rodata.*) }
    /DISCARD/ : { *(.eh_frame) *(.comment) *(.note*) }
}

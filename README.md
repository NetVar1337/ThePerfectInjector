# ThePerfectInjector
Literally, the perfect injector.

Detailed explanation: https://blog.can.ac/2018/05/02/making-the-perfect-injector-abusing-windows-address-sanitation-and-cow/

## This fork

Hardened and modernised against the detection surface that has grown since 2018. The
technique is unchanged — payload lives outside the user address range, execution happens
on a legitimate game thread, no handle is required and the vulnerable driver is gone
before the target starts — but the surrounding artifacts are gone.

### Mapper (`SimpleMapper.h`)

| Before | Now |
|---|---|
| Import shellcode called `LoadLibraryA`/`GetProcAddress` **inside the target** | Imports are resolved at map time from the injector (per-boot ASLR makes the addresses identical), the target runs no loader code and gains no modules |
| `assert(!ordinal)` → release builds crashed on ordinal imports | Ordinals supported and resolved |
| `__security_cookie` left at the default → `/GS` payloads died in `__report_gsfailure` | Cookie (and its complement) randomised per map |
| Full PE header page kept resident in the kernel allocation (a standing MZ/PE signature for pool scanners) | Headers wiped after mapping |
| Stub bytes hand-encoded with hardcoded RIP-relative offsets | Built by a small assembler, every displacement computed |
| Unbounded spin locks → a dead injector hung the game forever | Bounded waits, timeout falls through to the original function |
| Pages exposed RWX | Per-page permissions come from the section characteristics: code is RX, data is RW, never both |

The `call`/`ret` pair around the payload entry stays balanced, so hardware shadow stacks
(CET) do not trip a `#CP`, and the entry is invoked with a 16-byte aligned frame.

### Injector (`PerfectInjector.cpp`)

* **No reconnaissance APIs.** The target is found by walking `EPROCESS.ActiveProcessLinks`
  through the physical map. `CreateToolhelp32Snapshot` is only a fallback (`toolhelp` flag).
* **Per-process patching (optional).** `handle` mode writes through a process handle, which
  breaks copy-on-write, so the patched `kernel32` bytes are private to the target. The
  injector compares the PFN before/after and reports whether you actually got a private
  copy; on failure it falls back to the physical path automatically.
* **Shorter shared window.** The padding stub (which every other process executes while the
  hook is live) is restored as soon as the stub counter drains, not after a fixed sleep.
* **KVA shadow aware.** The exposed pages are wired into the *user* CR3 as well and the
  translation is verified. Flipping U/S bits in the kernel page tables alone does nothing
  for CPL3 when KVAS is enabled, which is the default on Intel since Meltdown.
* No `GetAsyncKeyState` polling (opt-in via `hotkey`), no `system("pause")`, no fixed
  sleeps on the critical path.

### Build

```
build.bat            # MSVC x64, produces PerfectInjector.exe
build_test.bat       # produces test_mapper.exe
test_mapper.exe      # maps a real system DLL and verifies the mapper end to end
```

`test_mapper.exe` checks relocations, IAT resolution (including ordinals), the security
cookie, the header wipe and the stub encoding against real system DLLs — e.g.
`test_mapper.exe C:\Windows\System32\urlmon.dll` exercises 95 ordinal imports.

### Payload build profile

The payload is mapped by hand and never touches the loader. Build it so it does not need
the loader either:

```
/MT /GS- /guard:cf- /EHs-c- /NODEFAULTLIB /ENTRY:PayloadEntry
```

* no static TLS, no delay imports, no CRT init that calls into the loader
* imports must be resolvable from modules already loaded in the injector
  (per-boot ASLR is what makes those addresses valid in the target)
* if the payload needs SEH, register the function table yourself; `.pdata`/`.tls` are
  not set up by the mapper (it warns when the image has them)

### Flags

```
noloadlib     never LoadLibrary in the injector either, unresolved imports are fatal
keepheaders   keep the PE headers (debugging)
toolhelp      fall back to CreateToolhelp32Snapshot for target discovery
handle        patch through a process handle (private CoW copy) instead of the physical map
hotkey        enable the F2/F1 key triggers
quiet         less output
pid=<n>       target by pid instead of name
```

### Signing

A code-signing certificate is a cheap way to make the *user-mode* surface legitimate: the
injector, the payload DLL and the bootstrapper can all carry a valid Authenticode
signature, so publisher/allowlist checks pass and the payload can be mapped as a genuinely
signed image instead of anonymous executable memory.

The kernel side does not benefit from a leaked certificate any more. Cross-signed roots are
retired and, from the April 2026 Windows driver policy updates, legacy cross-signed drivers
are not trusted by default — a new driver needs Microsoft attestation (WHCP / Hardware Dev
Center). Keep the driver path on "exploit an already attested signed driver" or a lab with
test signing, and spend the certificate on the user-mode components.

When signing anything: check revocation yourself (CRL/OCSP, `certutil -verify -urlfetch`) —
`osslsigncode` does not — check the EKU set (`1.3.6.1.5.5.7.3.3` code signing, and
`1.3.6.1.4.1.311.61.1.1` kernel mode if you still want that option), check that the
certificate is not already burned (present on VirusTotal with malware ⇒ it drags a known
bad reputation), and remember the timestamping service logs your file hash and IP.

### Known limitations

* Structured exception handling, static TLS and delay imports are not set up by the mapper.
* The kernel pool allocation is not freed (the driver is unloaded by design before the
  target starts); it lives until reboot.
* Patching shared pages at all is still a window, however short. `handle` mode removes it
  but costs a process handle with `PROCESS_VM_WRITE`.

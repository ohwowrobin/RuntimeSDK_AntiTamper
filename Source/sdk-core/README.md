# Korvayne Runtime — DLL core (canonical source)

The complete source for the `anticheat.dll`. Free and MIT-licensed — clone or download it from
GitHub (https://github.com/ohwowrobin/korvayne-latest), build, and drop the DLL into your game.
No license file, no activation, and no server: it arms at full capability out of the box.

Self-contained: everything needed to build and sign the DLL, and nothing else (the parent `acsdk\`
folder holds test fixtures + build artifacts).

| File | What |
|---|---|
| `acsdk.cpp` | The entire detection engine, telemetry, and access-check logic. Compiles to the DLL. |
| `acsdk.h` | The C API header used to build the DLL. The prebuilt SDK ships a clean-named copy as `anticheat.h`. |
| `acsdk_version.rc` | Windows version-info resource (CompanyName / ProductName / version). |
| `build_opensource.bat` | Builds the free DLL → `out\anticheat.dll`. |
| `SIGNING.md` | Optional: how to code-sign the built DLL if you want a signed binary. |

## Build
Run **`build_opensource.bat`** → produces `out\anticheat.dll` (hardened: Control Flow Guard, CET, version info).
Optionally code-sign it (see `SIGNING.md`), then copy it into your integration at
`sdk\bin\anticheat.dll`. The DLL is fully functional as built — no license or activation step.

## ValueGuard API
The stable core remains address-keyed 4-byte `U32`, but the DLL also exports typed convenience
wrappers: `AC_GuardI32` / `AC_SetGuardedI32` and `AC_GuardFloat` / `AC_SetGuardedFloat`. Legitimate
gameplay changes should use the write-through setters; `AC_NoteLegit*` is only a fallback after a
legacy direct write.

## Optional backend and signature updates
The SDK can optionally report to a **self-hostable analysis backend** and pull **signed detection-signature
updates** over an update channel. Both are optional/advanced and off by default — the DLL detects and
guards fully without them. Run your own backend if you want to aggregate and correlate detections
server-side; use the signature channel to keep detection rules current.

## Scope caveat
This is user-mode client integrity, not a kernel anti-cheat and not a standalone ban oracle. Treat its
signals as inputs: correlate detections server-side before acting on them.

## Source layout
`acsdk.cpp` is the detection engine. It builds the DLL directly from this folder — there is no separate
closed component. Contributions welcome via the GitHub repo above.

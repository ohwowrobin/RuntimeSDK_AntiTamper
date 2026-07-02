# Korvayne Runtime

**Free, open-source runtime anti-cheat & integrity SDK for indie games.**
Engine-agnostic, in-process, Shipping-stable. Drop one DLL next to your game — or build it yourself and read every line.

[![License: MIT](https://img.shields.io/badge/license-MIT-brightgreen)](LICENSE)

Korvayne Runtime used to be a paid product. It's now **MIT-licensed and free** — no license key, no activation, no server required. We're opening it up to give indie studios a real, auditable anti-cheat baseline and to build Korvayne into a name the community trusts.

---

## What's in this repo

| Folder | What it is |
|--------|------------|
| **`SDK/`** | The ready-to-ship anti-cheat — the exact drop-in package a studio integrates. Prebuilt `anticheat.dll` + headers + import lib, UE5 & Unity samples, optional server integration kit. Start here if you just want to *use* it. |
| **`Source/`** | The C++ SDK core (`sdk-core/`) — the detection engine that compiles to `anticheat.dll`. Start here to build, audit, or extend it. |

## Quick start (drop-in, zero code)

1. Grab `SDK/sdk/bin/anticheat.dll` (and `anticheat.ini.example` → `anticheat.ini`).
2. Ship `anticheat.dll` next to your game executable. It self-arms on load.
3. Route detections wherever you like via the cooperative C API (`SDK/sdk/include/anticheat.h`) — or just let the drop-in DLL run.

No license file. No network call home. It arms at full capability out of the box.

## Build it yourself

```bat
cd Source\sdk-core
build_opensource.bat        :: -> out\anticheat.dll  (MSVC / VS2022 x64)
```

## What it does

- **Universal detectors** (background thread): suspicious handles, injected/unsigned modules, memory-scan & hook shapes, anti-debug, code-integrity, self-protection.
- **Cooperative ValueGuard** — register the values you own (health/ammo/score); out-of-band writes are flagged and optionally restored.
- **SaveGame protection** — seal/verify serialized save payloads against casual editing.
- **Aim-behavior heuristics** — feed per-shot telemetry for aim-snap / triggerbot / wallhack signals.
- **Optional, self-hostable**: a signed detection-signature update channel and an analysis backend you can run yourself.

## Honest scope

Client-side, user-mode integrity raises the cost of cheating and gives you high-quality signals — it is **not** a kernel anti-cheat and not a standalone ban oracle. Treat detections as evidence to correlate server-side; keep authoritative game state on your backend.

## License

MIT — see [LICENSE](LICENSE). Use it in commercial or closed-source games, fork it, ship it. Attribution appreciated, not required.

Built by **Korvayne Solutions**. Website: https://korvayne.com

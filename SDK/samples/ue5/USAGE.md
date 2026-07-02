# Korvayne Runtime — Unreal Engine 5 wrapper

`ACTGuard.{h,cpp}` is a thin, drop-in wrapper over the cooperative API. All calls are no-ops if the
DLL didn't load, so they're always safe to call.

## 1. Load the DLL + resolve exports (once, at startup)
In a `UGameInstanceSubsystem` (or your GameInstance):
```cpp
#include "ACTGuard.h"
#include "HAL/PlatformProcess.h"

void UMyAcSubsystem::Initialize(FSubsystemCollectionBase& C)
{
    Super::Initialize(C);
    void* H = FPlatformProcess::GetDllHandle(TEXT("anticheat.dll"));        // next to the packaged exe
    if (!H) {
        const FString P = FPaths::ConvertRelativePathToFull(
            FPaths::Combine(FPaths::ProjectDir(), TEXT("Binaries/Win64/anticheat.dll")));
        H = FPlatformProcess::GetDllHandle(*P);                             // editor fallback
    }
    ACTGuard::Init(H);
    if (!ACTGuard::IsReady())
    {
        // For protected online play, fail closed here: block matchmaking/server join
        // and show a clean message instead of continuing without the runtime.
    }
}
```
Make sure `anticheat.dll` (+ optional `anticheat.ini`) is staged next to your packaged executable.

## 2. Guard the values cheaters target
In your character / weapon:
```cpp
// BeginPlay — register
ACTGuard::GuardFloat("health", &CurrentHP);
ACTGuard::GuardI32("ammo", &CurrentAmmo);

// on a sanctioned change — write-through (value + shadow atomic)
ACTGuard::SetGuardedFloat(&CurrentHP, NewHP);
ACTGuard::SetGuardedI32(&CurrentAmmo, NewAmmo);

// EndPlay — stop guarding before the actor dies
ACTGuard::UnguardFloat(&CurrentHP);
ACTGuard::UnguardI32(&CurrentAmmo);
```

## 3. Report aim telemetry (local player only)
On each shot, after you know whether it hit and whether you had line of sight:
```cpp
ACTGuard::ReportAim(AimSpeedDegPerMs, ReactionMs, HadLOS ? 1 : 0, Hit ? 1 : 0);
```
Never call this for AI-controlled pawns — the wrapper's `NotifyShotFired`/report path is meant for
the human player's shots only.

## 4. Protect local save payloads
Serialize your save game normally, then wrap the bytes before writing them to disk. Bind the save to
a stable context string such as player/account ID, slot, and schema version. Use the same context
when loading.

```cpp
TArray<uint8> Plain;
// Fill Plain with your serialized USaveGame data.

const FString SavePath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("profile.ksave"));
const FTCHARToUTF8 SavePathUtf8(*SavePath);
const char* Context = "player=account-123;slot=profile;schema=1";

int Rc = ACTGuard::ProtectSaveFile(SavePathUtf8.Get(), Plain.GetData(), Plain.Num(), Context);
if (Rc != 0)
{
    UE_LOG(LogTemp, Warning, TEXT("Korvayne save protect failed: %hs"), ACTGuard::SaveResultName(Rc));
}

TArray<uint8> Loaded;
Loaded.SetNumUninitialized(1024 * 1024);
unsigned LoadedLen = 0;
Rc = ACTGuard::VerifySaveFile(SavePathUtf8.Get(), Context, Loaded.GetData(), Loaded.Num(), &LoadedLen);
if (Rc == 0)
{
    Loaded.SetNum(LoadedLen);
    // Deserialize Loaded only after verification succeeded.
}
else
{
    UE_LOG(LogTemp, Warning, TEXT("Korvayne save rejected: %hs"), ACTGuard::SaveResultName(Rc));
}
```

## Notes
- The DLL self-arms on load (drop-in protection) at full capability even before you wire any of the
  above. No license, no key, no activation step.
- Enforcement policy (restore / eject) is configured in `anticheat.ini`, not in game code — though
  you can also implement your own response inside the detection callback (kick, disconnect, end match).
- Optional / advanced: the runtime can send telemetry to a self-hostable analysis backend and pull
  signed detection-signature updates from an update channel. Both are optional — the SDK works fully
  offline without either. See the repo for how to stand up the backend and configure the update feed.
- Scope: this is user-mode client integrity, not a kernel anti-cheat and not a standalone ban oracle.
  Treat its signals as evidence and correlate detections server-side before acting on them.

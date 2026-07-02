// ============================================================================
//  acsdk.h — portable anti-cheat SDK (Tier-1 universal detector core).
// ----------------------------------------------------------------------------
//  The "shared core" of the product: game-agnostic, process-inspection
//  detectors behind a clean C API. Link as a static lib or DLL; the game calls
//  AC_Init() once at startup, AC_Tick() per frame (cheap checks), AC_Shutdown()
//  on exit, and registers a detection callback that survives Shipping builds
//  (the sink is the SDK's own, NOT UE_LOG — fixes red-team finding U2/E).
//
//  Cooperative value-guard (Tier-2, per-game) lets the game register protected
//  values (health/ammo/score) that the SDK watches for out-of-band writes.
//  SaveGame protection lets the game sign + obfuscate serialized save payloads
//  so casual file edits, trainers, and save editors can be rejected on load.
//
//  C API so any engine (UE C++, native, or via P/Invoke) can integrate.
// ============================================================================
#ifndef ACSDK_H
#define ACSDK_H

#ifdef __cplusplus
extern "C" {
#endif

// Export/import decoration: define ACSDK_BUILD_DLL when building acsdk.dll,
// ACSDK_USE_DLL when consuming it as a DLL; neither for static linking.
#if defined(ACSDK_BUILD_DLL)
#  define ACSDK_API __declspec(dllexport)
#elif defined(ACSDK_USE_DLL)
#  define ACSDK_API __declspec(dllimport)
#else
#  define ACSDK_API
#endif

typedef enum {
    AC_SEV_INFO = 0,
    AC_SEV_LOW  = 1,
    AC_SEV_MED  = 2,
    AC_SEV_HIGH = 3,
    AC_SEV_CRIT = 4
} ac_severity;

typedef struct {
    const char*        sensor;      // "Handle", "CodeIntegrity", "ValueGuard", ...
    ac_severity        severity;
    float              confidence;  // 0.0 .. 1.0
    const char*        message;     // human-readable, already formatted
    unsigned long long detail;      // optional numeric (pid, access mask, addr)
} ac_detection;

// Detection sink. Called from the SDK's background scan thread (and AC_Tick).
// MUST be cheap + thread-safe on the game side. This is the Shipping-stable
// surface: route it to a signed file/IPC/backend, never to UE_LOG.
typedef void (*ac_detection_cb)(const ac_detection* det, void* user);

// Enforcement flags for ac_config.flags. Combine with |. The detection callback
// is always invoked first, so an integrator can layer their own response (kick,
// disconnect, telemetry) on top of — or instead of — these built-in policies.
#define AC_FLAG_VALUEGUARD_RESTORE  0x1u   // on out-of-band write, restore the legit
                                           // value (block the cheat effect, not just report)
#define AC_FLAG_TERMINATE_ON_TAMPER 0x2u   // on a confirmed HIGH/CRIT detection, terminate
                                           // the host process (eject the cheater)
#define AC_FLAG_EJECT_ON_READER     0x4u   // also eject on an unsigned external *reader*
                                           // (read-only handle, ESP-shape). Higher-FP: opt-in.

typedef struct {
    ac_detection_cb cb;               // required: where detections go
    void*           user;             // passed back to cb
    unsigned        scan_interval_ms; // background sensor cadence (0 -> default 750)
    unsigned        flags;            // AC_FLAG_* enforcement options
    const char*     license;          // signed license token (offline-verified). NULL ->
                                      // the SDK loads "anticheat.lic" next to the host exe.
} ac_config;

// Lifecycle. AC_Init starts the background scan thread + arms all universal
// sensors. Returns 0 on success, negative on error. Idempotent-safe.
//   -1 bad args   -2 thread start failed   -3 UNLICENSED (token missing/invalid/expired:
//   sensors are NOT armed — fail-closed product gate — but the host is never crashed;
//   a later AC_Init with a valid license arms normally). The -3 gate is only enforced in
//   builds compiled with ACSDK_REQUIRE_LICENSE (the shipping artifact); dev/test builds
//   log the verdict and arm anyway so the engine can be exercised offline.
ACSDK_API int  AC_Init(const ac_config* cfg);
ACSDK_API void AC_Tick(void);        // per-frame cheap checks (optional but recommended)
ACSDK_API void AC_Shutdown(void);

// Runtime context used by structured telemetry and access-check requests.
// Values are copied by the SDK. They are non-secret client/game context; do not
// pass server secrets here.
ACSDK_API void AC_SetGameId(const char* value);
ACSDK_API void AC_SetEnvironment(const char* value);
ACSDK_API void AC_SetIdentityProvider(const char* value);
ACSDK_API void AC_SetPlayerId(const char* value);
ACSDK_API void AC_SetSessionId(const char* value);
ACSDK_API void AC_SetPlatformUserId(const char* value);
ACSDK_API void AC_SetGameBuild(const char* value);
ACSDK_API void AC_SetTelemetryToken(const char* value);

// ---- Cooperative value guard (Tier-2, per-game) — ADDRESS-KEYED -------------
// Register a 32-bit value the game owns; the SDK keeps a per-session-keyed shadow
// and flags any write that did not go through AC_NoteLegit. Address-keyed so the
// game never tracks an id (matches the ACModule cooperative API).
ACSDK_API void AC_GuardU32(const char* name, volatile unsigned* addr);  // register (e.g. at BeginPlay)
ACSDK_API void AC_NoteLegit(volatile unsigned* addr);                   // call right after a legit write
ACSDK_API void AC_Unguard(volatile unsigned* addr);                    // before the address dies (EndPlay)
// Write-through setter (preferred): updates value + shadow atomically so legit
// writes can never desync. Use this instead of a raw write + AC_NoteLegit.
ACSDK_API void AC_SetGuardedU32(volatile unsigned* addr, unsigned val);

// Typed ValueGuard helpers. These are real DLL exports, implemented as thin
// wrappers over the stable 4-byte U32 core so integrators do not need to hand-roll
// casts or float bit-pattern conversion. Use SetGuarded* for every legitimate
// gameplay write. NoteLegit* is a fallback only after legacy direct writes.
ACSDK_API void AC_GuardI32(const char* name, volatile int* addr);
ACSDK_API void AC_NoteLegitI32(volatile int* addr);
ACSDK_API void AC_UnguardI32(volatile int* addr);
ACSDK_API void AC_SetGuardedI32(volatile int* addr, int val);
ACSDK_API void AC_GuardFloat(const char* name, volatile float* addr);
ACSDK_API void AC_NoteLegitFloat(volatile float* addr);
ACSDK_API void AC_UnguardFloat(volatile float* addr);
ACSDK_API void AC_SetGuardedFloat(volatile float* addr, float val);

// ---- Cooperative behavior hook (Tier-3 advisory) ---------------------------
// The game reports per-shot aim telemetry; the SDK runs advisory aim-snap /
// triggerbot / wallhack heuristics on those reported values.
//   aimSpeedPerMs : crosshair speed just before the shot
//   reactionMs    : time since the target was acquired
//   hadLineOfSight: 0/1   hit: 0/1
ACSDK_API void AC_ReportAim(float aimSpeedPerMs, float reactionMs, int hadLineOfSight, int hit);

// ---- Cooperative SaveGame protection --------------------------------------
// Wrap a game-owned save payload in a Korvayne envelope and verify it on load.
// The SDK does not decide how to serialize your game state. Pass the serialized
// bytes plus a stable context string, for example:
//   "player=<account-id>;slot=campaign-1;schema=2"
// Use the same context when verifying. Changing the context intentionally makes
// old protected saves fail verification, which prevents easy cross-player/slot
// copy attacks. Return codes:
//   0 ok
//  -1 bad args
//  -2 output buffer too small (out_len receives required size when possible)
//  -3 crypto/runtime failure
//  -4 tampered, wrong context, or unsupported protected-save envelope
//  -5 file I/O failed
//  -6 SDK runtime is not licensed/armed
//  -7 SaveGame protection is disabled by runtime policy
#define AC_SAVE_OK                0
#define AC_SAVE_BAD_ARGS         -1
#define AC_SAVE_BUFFER_TOO_SMALL -2
#define AC_SAVE_CRYPTO_FAILED    -3
#define AC_SAVE_TAMPERED         -4
#define AC_SAVE_IO_FAILED        -5
#define AC_SAVE_UNLICENSED       -6
#define AC_SAVE_DISABLED         -7
ACSDK_API int AC_ProtectSaveBuffer(const void* plain, unsigned plain_len, const char* context,
                                   void* out_protected, unsigned out_cap, unsigned* out_len);
ACSDK_API int AC_VerifySaveBuffer(const void* protected_buf, unsigned protected_len, const char* context,
                                  void* out_plain, unsigned out_cap, unsigned* out_len);
ACSDK_API int AC_ProtectSaveFile(const char* path, const void* plain, unsigned plain_len, const char* context);
ACSDK_API int AC_VerifySaveFile(const char* path, const char* context,
                                void* out_plain, unsigned out_cap, unsigned* out_len);
ACSDK_API const char* AC_SaveResultName(int rc);

// Build/version info (per-build keying lives here in the product build).
ACSDK_API const char* AC_Version(void);

#ifdef __cplusplus
}
#endif
#endif // ACSDK_H

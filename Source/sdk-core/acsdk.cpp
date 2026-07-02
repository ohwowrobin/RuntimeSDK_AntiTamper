// ============================================================================
//  acsdk.cpp â€” Tier-1 universal detector core implementation.
//  Slice 1: central sink (Shipping-stable, callback-based) + cooperative
//  ValueGuard (per-session key) + the HARDENED Handle sensor.
//
//  Handle sensor fixes red-team findings A/B/C in one unified design:
//   * A (fail-open): confirm "handle targets us" by matching the kernel Object
//     pointer of the handle against our OWN process object â€” no OpenProcess on
//     the holder is needed to confirm. A holder we cannot inspect is treated as
//     MORE suspicious (fail closed), not waved through.
//   * B (basename allowlist) + C (parent trust): trust is decided ONLY by
//     Authenticode signature of the holder image (WinVerifyTrust), never by
//     image name or parent-PID. A cheat named explorer.exe is unsigned -> flagged.
//   * FP: validly-signed holders (legit overlays/AV/system) are suppressed, so
//     real-world signed software does not generate noise.
//
//  Build (lib + standalone test):
//   cl /nologo /EHsc /O2 /std:c++17 /DAC_STANDALONE_TEST acsdk.cpp
//      /link wintrust.lib
// ============================================================================
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstddef>
#include <ctime>
#include <cctype>
#include <new>
#include "acsdk.h"

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

// ---------------------------------------------------------------------------
//  NT definitions (EX handle table; do not pull <winternl.h>)
// ---------------------------------------------------------------------------
typedef LONG NTSTATUS;
static const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = (NTSTATUS)0xC0000004L;
static const ULONG    SystemExtendedHandleInformation = 0x40;

typedef struct _AC_SYS_HANDLE_EX {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} AC_SYS_HANDLE_EX;
typedef struct _AC_SYS_HANDLE_INFO_EX {
    ULONG_PTR        NumberOfHandles;
    ULONG_PTR        Reserved;
    AC_SYS_HANDLE_EX Handles[1];
} AC_SYS_HANDLE_INFO_EX;
typedef NTSTATUS (NTAPI* NtQSI_t)(ULONG, PVOID, ULONG, PULONG);

// Resolve a holder's image path WITHOUT opening it (works for PPL/protected).
static const ULONG SystemProcessIdInformation = 0x58;
typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } AC_USTRING;
typedef struct { HANDLE ProcessId; AC_USTRING ImageName; } AC_SYS_PROCID_INFO;

static const ULONG AC_DANGEROUS_MASK =
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
    PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE;

// ---------------------------------------------------------------------------
//  SDK state
// ---------------------------------------------------------------------------
static ac_config        g_cfg;
static CRITICAL_SECTION g_lock;
static bool             g_lockInit = false;
static volatile LONG    g_running  = 0;
static HANDLE           g_thread   = nullptr;
static NtQSI_t          g_NtQSI    = nullptr;
typedef NTSTATUS (NTAPI* NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NtQIP_t          g_NtQIP    = nullptr;   // NtQueryInformationProcess (resolved in AC_Init)
static uint32_t         g_sessionKey = 0;   // per-session ValueGuard key (NOT static)
static INIT_ONCE        g_initOnce = INIT_ONCE_STATIC_INIT;  // abandonment-safe one-time core init
static volatile LONG    g_started  = 0;     // set once the scan threads exist (AC_Init idempotency)
static bool             g_terminateOnTamper = false;  // AC_FLAG_TERMINATE_ON_TAMPER (eject)
static bool             g_ejectOnReader     = false;  // AC_FLAG_EJECT_ON_READER (eject on unsigned reader)
static void EjectHost(const char* reason);            // defined after ac_emit; eject helper

enum AcHandleResponse {
    AC_HANDLE_CORROBORATED = 0,  // handles report; auto-eject only after corroboration
    AC_HANDLE_TERMINATE_WRITE,   // eject on unsigned write/inject-class handles when eject is enabled
    AC_HANDLE_TERMINATE_READER   // also eject on unsigned read-only handles (highest FP risk)
};
static AcHandleResponse g_handleResponse = AC_HANDLE_CORROBORATED;

enum AcSensorResponse {
    AC_RESP_REPORT = 0,
    AC_RESP_CORROBORATED,
    AC_RESP_TERMINATE
};
enum AcModuleResponse {
    AC_MODULE_REPORT = 0,
    AC_MODULE_CORROBORATED,
    AC_MODULE_TERMINATE_HIGH,
    AC_MODULE_TERMINATE_UNSIGNED
};
static AcModuleResponse g_moduleResponse = AC_MODULE_REPORT;
static AcSensorResponse g_memoryResponse = AC_RESP_REPORT;
static AcSensorResponse g_hookResponse = AC_RESP_REPORT;
static AcSensorResponse g_debuggerResponse = AC_RESP_REPORT;
static AcSensorResponse g_selfProtectResponse = AC_RESP_REPORT;
static AcSensorResponse g_behaviorResponse = AC_RESP_REPORT;
static char             g_backendHost[64] = "127.0.0.1";
static int              g_backendPort = 8000;
// Online activation / revocation (Step 5). Opt-in; uses the baked backend host. Fail-OPEN by design:
// only a definitive "revoked"/"expired" from the backend denies arming â€” an unreachable backend
// falls back to the offline license verdict so air-gapped / LAN-tournament installs still work.
static bool             g_activate = false;
// License / per-build keying (Step 2). g_buildKey is the unique per-build key carried in
// the (offline-verified) license. It is only sent to Korvayne activation/revocation, not to
// studio telemetry or access-check endpoints. Empty until a valid license is verified in AC_Init.
static char             g_buildKey[80] = {0};
// License-derived entitlement (set by AcLicenseGate on a valid license). g_licensed gates
// whether feature-capping applies (a dev/ungated unlicensed build keeps its cfg flags so it
// stays testable). The g_licFeat* flags are the features the license PERMITS; AC_Init masks
// the integrator's requested enforcement flags down to these (a tier-1 token can't unlock
// tier-2 enforcement just because the integrator set the flag).
static bool             g_licensed       = false;
static int              g_licTier        = 0;
static bool             g_licFeatRestore = false;
static bool             g_licFeatEject   = false;
static bool             g_licFeatReader  = false;
static volatile LONG    g_licenseRuntimeOk = 0;
static char             g_licenseId[17] = {0};      // short SHA-256 fingerprint of the signed token
static char             g_licenseCustomer[96] = {0};
static char             g_licenseTitle[64] = {0};

struct AcRuntimeContext {
    char gameId[96];
    char environment[32];
    char identityProvider[32];
    char playerId[128];
    char sessionId[128];
    char platformUserId[128];
    char gameBuild[64];
    bool requireVerifiedIdentity;
};
static AcRuntimeContext g_ctx = { "", "production", "custom", "", "", "", "", true };

struct AcEndpoint {
    bool enabled;
    bool secure;
    wchar_t host[256];
    wchar_t path[512];
    INTERNET_PORT port;
    int timeoutMs;
};
static AcEndpoint g_telemetryEndpoint = { false, true, L"", L"/", INTERNET_DEFAULT_HTTPS_PORT, 2500 };
static AcEndpoint g_accessEndpoint = { false, true, L"", L"/", INTERNET_DEFAULT_HTTPS_PORT, 2500 };

struct AcTelemetryPolicy {
    ac_severity minSeverity;
    int batchIntervalMs;
    char authHeader[64];
    char authToken[256];
    bool redactPaths;
    bool eventInjection;
    bool eventHooks;
    bool eventHandles;
    bool eventDebugger;
    bool eventBoot;
    bool eventMemory;
    bool eventSdkIntegrity;
    bool eventProtectedValue;
    bool eventAccessCheck;
    bool eventAimBehavior;
    bool eventSaveGame;
    bool fieldPlayerId;
    bool fieldSessionId;
    bool fieldPlatformUserId;
    bool fieldGameBuild;
    bool fieldSdkVersion;
    bool fieldModuleHash;
    bool fieldModuleSigner;
    bool fieldActionTaken;
    bool fieldServerObservedIp;
    bool fieldHardwareId;
    bool fieldProcessNames;
};
static AcTelemetryPolicy g_tel = {
    AC_SEV_LOW, 5000, "Authorization", "", true,
    true, true, true, true, true, true, true, false, true, true, true,
    true, true, true, true, true, true, true, true, true,
    false, false
};

static bool g_valueGuardEnabled = false;
static bool g_valueGuardTerminate = false;
static ac_severity g_valueGuardSeverity = AC_SEV_MED;
static unsigned g_valueGuardMaxTracked = 128;
static bool g_saveGameEnabled = true;
static bool g_saveGameObfuscate = true;
static ac_severity g_saveGameTamperSeverity = AC_SEV_HIGH;
static unsigned g_saveGameMaxBytes = 1024 * 1024;
static char g_accessFailMode[24] = "allow";
static char g_accessOnBanned[32] = "block_start";
static char g_accessOnSessionBan[32] = "disconnect";
static char g_accessProvider[32] = "studio_backend";
static char g_accessMode[32] = "startup_and_recheck";
static int  g_accessRecheckIntervalSec = 300;
static char g_appealUrl[256] = "";

static void CopyClean(char* dst, size_t dstN, const char* src) {
    if (!dst || dstN == 0) return;
    dst[0] = 0;
    if (!src) return;
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 1 < dstN; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\r' || c == '\n' || c == '\t') continue;
        if (c < 32) continue;
        dst[j++] = (char)c;
    }
    dst[j] = 0;
}

// Idempotent, lock-free core init: the lock + session key MUST exist before any
// public entry point runs. A game can register a guarded value (BeginPlay) the
// instant it resolves the export â€” BEFORE the auto-init bootstrap thread runs â€”
// so every guard API and DllMain call this first. Initialising the session key
// here (once, eagerly) also means AC_Init can never re-key and desync a value
// that was registered early. InitializeCriticalSection is loader-lock-safe.
static BOOL CALLBACK CoreInitOnce(PINIT_ONCE, PVOID, PVOID*) {
    InitializeCriticalSection(&g_lock);
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    g_sessionKey = (uint32_t)(q.LowPart ^ (q.HighPart * 2654435761u) ^ (GetCurrentProcessId() * 40503u));
#ifdef ACSDK_BUILD_SALT
    // Per-build keying (compile-time): each customer's build is compiled with a distinct
    //   -DACSDK_BUILD_SALT=0x........  so the ValueGuard obfuscation diverges per build even
    // before the runtime license mixes in (below, AcBindSessionKey). A cheat reverse-engineered
    // against one customer's build does not transfer to another's. (See also the per-license
    // build key folded in at AC_Init.)
    g_sessionKey ^= (uint32_t)(ACSDK_BUILD_SALT);
#endif
    if (g_sessionKey == 0) g_sessionKey = 0xA5A5A5A5u;
#if defined(ACSDK_BACKEND_HOST)
    strncpy(g_backendHost, ACSDK_BACKEND_HOST, sizeof(g_backendHost) - 1); g_backendHost[sizeof(g_backendHost) - 1] = 0;
  #if defined(ACSDK_BACKEND_PORT)
    g_backendPort = (ACSDK_BACKEND_PORT);
  #else
    g_backendPort = 443;
  #endif
#endif
#ifdef ACSDK_BACKEND_HOST_FROM_ENV
    // DEV/TEST ONLY. Shipping builds (this flag undefined) ignore env/ini host overrides
    char host[64] = {0};
    DWORD hn = GetEnvironmentVariableA("AC_BACKEND_HOST", host, sizeof(host));
    if (hn > 0 && hn < sizeof(host)) { strncpy(g_backendHost, host, sizeof(g_backendHost) - 1); g_backendHost[sizeof(g_backendHost) - 1] = 0; }
    char port[16] = {0};
    if (GetEnvironmentVariableA("AC_BACKEND_PORT", port, sizeof(port)) > 0) { int p = atoi(port); if (p > 0 && p < 65536) g_backendPort = p; }
    char act[8] = {0};
    if (GetEnvironmentVariableA("AC_ACTIVATE", act, sizeof(act)) > 0 && act[0] == '1') g_activate = true;
#endif
#ifdef ACSDK_ACTIVATE
    g_activate = true;   // SHIPPING: enable the online activation/revocation check.
#endif
    g_lockInit = true;
    return TRUE;
}
// Idempotent, abandonment-safe core init. InitOnce handles a suspended/killed initialiser
// without the "busy-spin g_coreInit != 2 forever" deadlock the hand-rolled CAS had, and is
// loader-lock-safe (the callback takes no loader lock).
static void EnsureCoreInit() {
    InitOnceExecuteOnce(&g_initOnce, CoreInitOnce, nullptr, nullptr);
}

// ---- detection sink: thread-safe, FNV de-dup with 3s cooldown --------------
struct Recent { uint32_t h; ULONGLONG t; };
static Recent g_recent[128] = {};
static uint32_t fnv1a(const char* s) { uint32_t h = 2166136261u; while (*s) h = (h ^ (uint8_t)*s++) * 16777619u; return h; }

static bool AcRuntimeLicensed() {
    return true;   // open-source build: no licensing; SaveGame protection is always available
}

static void AcClearLicenseRuntime() {
    InterlockedExchange(&g_licenseRuntimeOk, 0);
    g_buildKey[0] = 0;
    g_licenseId[0] = 0;
    g_licenseCustomer[0] = 0;
    g_licenseTitle[0] = 0;
    g_licensed = false;
    g_licTier = 0;
    g_licFeatRestore = false;
    g_licFeatEject = false;
    g_licFeatReader = false;
}

static AcSensorResponse ResponseForSensor(const char* sensor) {
    if (!sensor) return AC_RESP_REPORT;
    if (!strcmp(sensor, "Handle")) return AC_RESP_CORROBORATED;
    if (!strcmp(sensor, "MemScan")) return g_memoryResponse;
    if (!strcmp(sensor, "CodeIntegrity")) return g_hookResponse;
    if (!strcmp(sensor, "Module")) {
        if (g_moduleResponse == AC_MODULE_CORROBORATED) return AC_RESP_CORROBORATED;
        if (g_moduleResponse == AC_MODULE_TERMINATE_HIGH ||
            g_moduleResponse == AC_MODULE_TERMINATE_UNSIGNED) return AC_RESP_TERMINATE;
        return AC_RESP_REPORT;
    }
    if (!strcmp(sensor, "AntiDbg")) return g_debuggerResponse;
    if (!strcmp(sensor, "SelfProtect")) return g_selfProtectResponse;
    if (!strcmp(sensor, "AimSnap") || !strcmp(sensor, "Triggerbot") || !strcmp(sensor, "Wallhack")) {
        return g_behaviorResponse;
    }
    if (!strcmp(sensor, "ValueGuard")) return g_valueGuardTerminate ? AC_RESP_TERMINATE : AC_RESP_REPORT;
    return AC_RESP_REPORT;
}

// Corroboration gate for AUTO-TERMINATE. Per-category response config decides whether
// a HIGH/CRIT event is report-only, corroboration evidence, or immediately terminal.
// Called under g_lock.
static bool EjectEligible(const char* sensor, ac_severity sev) {
    if (sev < AC_SEV_HIGH) return false;
    AcSensorResponse response = ResponseForSensor(sensor);
    if (response == AC_RESP_REPORT) return false;
    if (response == AC_RESP_TERMINATE) return true;
    static const char* seen[8] = { 0 }; static ULONGLONG seenT[8] = { 0 };
    const ULONGLONG now = GetTickCount64(), WIN = 20000;
    for (int i = 0; i < 8; i++) if (seen[i] && now - seenT[i] > WIN) seen[i] = 0;
    int slot = -1;
    for (int i = 0; i < 8; i++) if (seen[i] && !strcmp(seen[i], sensor)) { slot = i; break; }
    if (slot < 0) for (int i = 0; i < 8; i++) if (!seen[i]) { seen[i] = sensor; slot = i; break; }
    if (slot >= 0) seenT[slot] = now;
    int distinct = 0; for (int i = 0; i < 8; i++) if (seen[i]) distinct++;
    return distinct >= 2;
}

// Cross-sensor corroboration window (best-effort): the last few DISTINCT sensors that produced a
// MED+ detection, with timestamps. Used to gate the aggressive eject_on_reader response so a single
// uncorroborated read-only-handle signal (overlays/capture tools look identical to an ESP reader)
// can never terminate a paying customer's game on its own. Both callers hold g_lock.
static const char* g_corrSensor[8] = { 0 };
static ULONGLONG   g_corrT[8] = { 0 };
static const ULONGLONG AC_CORR_WIN = 20000;
static void CorrNote(const char* sensor, ac_severity sev) {
    if (sev < AC_SEV_MED) return;
    const ULONGLONG now = GetTickCount64();
    for (int i = 0; i < 8; i++) if (g_corrSensor[i] && now - g_corrT[i] > AC_CORR_WIN) g_corrSensor[i] = 0;
    int slot = -1;
    for (int i = 0; i < 8; i++) if (g_corrSensor[i] && !strcmp(g_corrSensor[i], sensor)) { slot = i; break; }
    if (slot < 0) for (int i = 0; i < 8; i++) if (!g_corrSensor[i]) { g_corrSensor[i] = sensor; slot = i; break; }
    if (slot >= 0) g_corrT[slot] = now;
}
// True iff a DIFFERENT sensor also produced a MED+ detection within the window.
static bool CorrCorroborated(const char* selfSensor) {
    const ULONGLONG now = GetTickCount64();
    for (int i = 0; i < 8; i++)
        if (g_corrSensor[i] && now - g_corrT[i] <= AC_CORR_WIN && strcmp(g_corrSensor[i], selfSensor)) return true;
    return false;
}

static void ac_emit(const char* sensor, ac_severity sev, float conf, const char* msg, unsigned long long detail) {
    EnterCriticalSection(&g_lock);
    ac_detection_cb cb = g_cfg.cb; void* user = g_cfg.user;   // snapshot under lock (no torn read vs re-AC_Init)
    bool dup = false;
    if (cb) {
        uint32_t key = fnv1a(sensor) ^ fnv1a(msg);
        ULONGLONG now = GetTickCount64();
        for (auto& r : g_recent) if (r.h == key && now - r.t < 3000) { dup = true; break; }
        if (!dup) {
            size_t idx = 0; ULONGLONG oldest = ~0ull;
            for (size_t i = 0; i < 128; i++) if (g_recent[i].t < oldest) { oldest = g_recent[i].t; idx = i; }
            g_recent[idx] = { key, now };
        }
    }
    CorrNote(sensor, sev);   // record for cross-sensor corroboration (gates eject_on_reader)
    AcSensorResponse response = ResponseForSensor(sensor);
    bool directEject = (sev >= AC_SEV_HIGH && response == AC_RESP_TERMINATE);
    bool doEject = (AcRuntimeLicensed() && !dup && g_terminateOnTamper && EjectEligible(sensor, sev));
    LeaveCriticalSection(&g_lock);
    if (!cb || dup) return;
    ac_detection d; d.sensor = sensor; d.severity = sev; d.confidence = conf; d.message = msg; d.detail = detail;
    cb(&d, user);

    // Enforcement: terminate only on a CORROBORATED tamper (see EjectEligible). The
    // detection above was delivered first so telemetry/backends always see it.
    if (doEject) EjectHost(directEject
        ? "ejecting cheater: configured high-confidence response - terminating host process"
        : "ejecting cheater: corroborated tamper - terminating host process");
}

// Shared eject: announce via the sink (so telemetry sees the reason) then hard-kill
// the host. Called for HIGH/CRIT tampers and, when AC_FLAG_EJECT_ON_READER is set,
// for an unsigned external reader.
static void EjectHost(const char* reason) {
    EnterCriticalSection(&g_lock);
    ac_detection_cb cb = g_cfg.cb; void* user = g_cfg.user;   // snapshot under lock
    LeaveCriticalSection(&g_lock);
    if (!AcRuntimeLicensed()) {
        if (cb) {
            ac_detection e; e.sensor = "Enforce"; e.severity = AC_SEV_INFO; e.confidence = 1.0f;
            e.message = "enforcement skipped: SDK runtime is not licensed/armed"; e.detail = 0;
            cb(&e, user);
        }
        return;
    }
    if (cb) {
        ac_detection e; e.sensor = "Enforce"; e.severity = AC_SEV_CRIT; e.confidence = 1.0f;
        e.message = reason; e.detail = 0;
        cb(&e, user);
    }
    TerminateProcess(GetCurrentProcess(), 0xACC0DEADu);
}

// ---------------------------------------------------------------------------
//  Trust anchor: CATALOG-AWARE Authenticode verification (replaces name/parent
//  trust). System binaries (csrss/conhost/System32) are catalog-signed, NOT
//  embedded â€” so we check both. Plus handle-less path resolution so PPL and
//  DACL-stripped holders can still be identified + signature-checked.
// ---------------------------------------------------------------------------
static LONG VerifyEmbeddedStatus(const wchar_t* path) {
    WINTRUST_FILE_INFO fi; ZeroMemory(&fi, sizeof(fi));
    fi.cbStruct = sizeof(fi); fi.pcwszFilePath = path;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd; ZeroMemory(&wd, sizeof(wd));
    wd.cbStruct = sizeof(wd); wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi; wd.dwStateAction = WTD_STATEACTION_VERIFY; wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    LONG st = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    return st;   // ERROR_SUCCESS = trusted; other codes distinguished by ClassifySig()
}
static bool VerifyCatalog(HANDLE hFile, const wchar_t* memberPath) {
    HCATADMIN hAdmin = nullptr;
    if (!CryptCATAdminAcquireContext2(&hAdmin, nullptr, L"SHA256", nullptr, 0)) return false;
    DWORD cb = 0; CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &cb, nullptr, 0);
    bool result = false;
    if (cb) {
        std::vector<BYTE> hash(cb);
        if (CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &cb, hash.data(), 0)) {
            std::wstring tag; wchar_t hx[3];
            for (DWORD i = 0; i < cb; i++) { swprintf(hx, 3, L"%02X", hash[i]); tag += hx; }
            HCATINFO hCat = CryptCATAdminEnumCatalogFromHash(hAdmin, hash.data(), cb, 0, nullptr);
            if (hCat) {
                CATALOG_INFO ci; ci.cbStruct = sizeof(ci);
                if (CryptCATCatalogInfoFromContext(hCat, &ci, 0)) {
                    WINTRUST_CATALOG_INFO wci; ZeroMemory(&wci, sizeof(wci)); wci.cbStruct = sizeof(wci);
                    wci.pcwszCatalogFilePath = ci.wszCatalogFile; wci.pcwszMemberFilePath = memberPath;
                    wci.pcwszMemberTag = tag.c_str(); wci.hMemberFile = hFile;
                    wci.pbCalculatedFileHash = hash.data(); wci.cbCalculatedFileHash = cb; wci.hCatAdmin = hAdmin;
                    WINTRUST_DATA wd; ZeroMemory(&wd, sizeof(wd)); wd.cbStruct = sizeof(wd);
                    wd.dwUIChoice = WTD_UI_NONE; wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
                    wd.dwUnionChoice = WTD_CHOICE_CATALOG; wd.pCatalog = &wci;
                    wd.dwStateAction = WTD_STATEACTION_VERIFY; wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
                    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                    LONG st = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
                    wd.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
                    result = (st == ERROR_SUCCESS);
                }
                CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
            }
        }
    }
    CryptCATAdminReleaseContext(hAdmin, 0);
    return result;
}
// Distinguish a real "unsigned/tampered" verdict from a transient verify error
// (chain/cache/IO failure). A verify error must NOT be treated as unsigned â€”
// that is the fresh-install / offline / tournament-PC false-positive class.
enum SigVerdict { SIG_TRUSTED, SIG_UNTRUSTED, SIG_UNKNOWN };
static const LONG AC_TRUST_E_NOSIGNATURE = (LONG)0x800B0100L;
static const LONG AC_TRUST_E_BAD_DIGEST  = (LONG)0x80096010L;
static const LONG AC_CERT_E_REVOKED      = (LONG)0x800B010CL;  // definitively revoked signer
static const LONG AC_CERT_E_REVOCATION_FAILURE = (LONG)0x800B010EL;  // chain valid, revocation uncheckable (offline)
static SigVerdict ClassifySig(const wchar_t* path, HANDLE hFile) {
    LONG est = VerifyEmbeddedStatus(path);
    if (est == ERROR_SUCCESS) return SIG_TRUSTED;
    if (hFile != INVALID_HANDLE_VALUE && VerifyCatalog(hFile, path)) return SIG_TRUSTED;
    if (est == AC_CERT_E_REVOKED) return SIG_UNTRUSTED;   // definitively revoked (e.g. stolen-then-revoked cheat cert) -> accuse
    // Chain validated but revocation couldn't be checked offline -> TRUST: a valid signature
    // must not become "unknown"/noisy just because a CRL wasn't cached (the fresh-install /
    // offline / tournament-PC low-FP class). Only a DEFINITE revocation above flips it.
    if (est == AC_CERT_E_REVOCATION_FAILURE) return SIG_TRUSTED;
    if (est == AC_TRUST_E_NOSIGNATURE || est == AC_TRUST_E_BAD_DIGEST) return SIG_UNTRUSTED;
    return SIG_UNKNOWN;   // verify could not complete -> do not accuse
}
static bool ResolveNtPath(DWORD pid, wchar_t* out, DWORD cch) {
    if (!g_NtQSI) return false;
    std::vector<wchar_t> nbuf(cch ? cch : 1024);
    AC_SYS_PROCID_INFO info; info.ProcessId = (HANDLE)(ULONG_PTR)pid;
    info.ImageName.Length = 0; info.ImageName.MaximumLength = (USHORT)(nbuf.size() * sizeof(wchar_t)); info.ImageName.Buffer = nbuf.data();
    NTSTATUS st = g_NtQSI(SystemProcessIdInformation, &info, sizeof(info), nullptr);
    if (st == STATUS_INFO_LENGTH_MISMATCH) {
        USHORT need = info.ImageName.MaximumLength;
        nbuf.assign((size_t)need / sizeof(wchar_t) + 2, 0);
        info.ImageName.Length = 0; info.ImageName.MaximumLength = (USHORT)(nbuf.size() * sizeof(wchar_t)); info.ImageName.Buffer = nbuf.data();
        st = g_NtQSI(SystemProcessIdInformation, &info, sizeof(info), nullptr);
    }
    if (st < 0) return false;
    USHORT chars = info.ImageName.Length / sizeof(wchar_t);
    if (chars == 0 || (DWORD)chars + 1 >= cch) return false;
    wcsncpy(out, info.ImageName.Buffer, chars); out[chars] = 0;
    return true;
}
enum HolderTrust { HT_TRUSTED, HT_UNTRUSTED, HT_UNKNOWN };
static HANDLE OpenForRead(const wchar_t* p) {
    return CreateFileW(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
}
// Resolve the holder image + verify its signature. Returns trust verdict; fills
// a UTF-8 display path. Only a holder we can resolve NEITHER way is HT_UNKNOWN.
static HolderTrust ClassifyHolder(DWORD pid, char* disp, size_t dispCch) {
    wchar_t wpath[1024] = {0}; HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hp) { DWORD cb = 1024; if (QueryFullProcessImageNameW(hp, 0, wpath, &cb)) hFile = OpenForRead(wpath); CloseHandle(hp); }
    if (hFile == INVALID_HANDLE_VALUE) {
        wchar_t nt[1024];
        if (ResolveNtPath(pid, nt, 1024)) {
            wchar_t gr[1100]; swprintf(gr, 1100, L"\\\\?\\GLOBALROOT%s", nt);
            hFile = OpenForRead(gr); wcsncpy(wpath, nt, 1023); wpath[1023] = 0;   // wcsncpy may not NUL-terminate
        }
    }
    if (wpath[0]) WideCharToMultiByte(CP_UTF8, 0, wpath, -1, disp, (int)dispCch, nullptr, nullptr);
    else          strncpy(disp, "<unresolved holder>", dispCch);
    if (dispCch) disp[dispCch - 1] = 0;   // WC2MB/strncpy may truncate a long/non-ASCII path WITHOUT terminating -> %s OOB read
    if (hFile == INVALID_HANDLE_VALUE) return HT_UNKNOWN;
    SigVerdict v = ClassifySig(wpath, hFile);   // verify-error -> UNKNOWN, not "untrusted"
    CloseHandle(hFile);
    return v == SIG_TRUSTED ? HT_TRUSTED : (v == SIG_UNTRUSTED ? HT_UNTRUSTED : HT_UNKNOWN);
}
// Catalog-aware signature verdict for a file path (reused by the Module sensor).
static SigVerdict ClassifyFileSig(const wchar_t* path) {
    HANDLE h = OpenForRead(path);
    SigVerdict v = ClassifySig(path, h);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    return v;
}

// ---------------------------------------------------------------------------
//  Shared bounded HTTP POST helper for telemetry, access checks, and activation.
// ---------------------------------------------------------------------------
static bool HttpPostCustom(const wchar_t* host, INTERNET_PORT port, const wchar_t* path, bool secure,
                           const wchar_t* contentType, const wchar_t* extraHeaders,
                           const void* body, DWORD len, std::string& out, int timeoutMs,
                           bool includeLicenseBuildHeader = false) {
    bool ok = false;
    HINTERNET hS = WinHttpOpen(L"KorvayneAC/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) return false;
    if (timeoutMs < 250) timeoutMs = 250;
    if (timeoutMs > 30000) timeoutMs = 30000;
    WinHttpSetTimeouts(hS, timeoutMs, timeoutMs, timeoutMs, timeoutMs);   // bound every phase
    HINTERNET hC = WinHttpConnect(hS, host, port, 0);
    if (hC) {
        // TLS for a real backend (port 443); plain HTTP only tolerated for a localhost dev
        // endpoint. Production telemetry/access endpoints MUST be HTTPS and authenticate
        // short-lived session tokens server-side.
        DWORD reqFlags = secure ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hR = WinHttpOpenRequest(hC, L"POST", path, nullptr, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES, reqFlags);
        if (hR) {
            // Only Korvayne activation/revocation receives the license build key. Studio-owned
            // telemetry/access endpoints receive license_id/license_tier in JSON, not the build key.
            wchar_t hdr[1024];
            const wchar_t* ct = contentType ? contentType : L"application/octet-stream";
            if (includeLicenseBuildHeader && g_buildKey[0]) {
                wchar_t wbk[160]; MultiByteToWideChar(CP_UTF8, 0, g_buildKey, -1, wbk, 160); wbk[159] = 0;
                swprintf(hdr, 1024, L"Content-Type: %s\r\nX-AC-Build: %s\r\n", ct, wbk);
            } else {
                swprintf(hdr, 1024, L"Content-Type: %s\r\n", ct);
            }
            if (extraHeaders && extraHeaders[0] && wcslen(hdr) + wcslen(extraHeaders) + 1 < _countof(hdr)) {
                wcscat_s(hdr, extraHeaders);
            }
            if (WinHttpSendRequest(hR, hdr, (DWORD)-1, (LPVOID)body, len, len, 0) &&
                WinHttpReceiveResponse(hR, nullptr)) {
                DWORD avail = 0;
                while (WinHttpQueryDataAvailable(hR, &avail) && avail) {
                    size_t off = out.size(); out.resize(off + avail); DWORD rd = 0;
                    if (!WinHttpReadData(hR, &out[off], avail, &rd)) { out.resize(off); break; }
                    out.resize(off + rd);
                }
                ok = true;
            }
            WinHttpCloseHandle(hR);
        }
        WinHttpCloseHandle(hC);
    }
    WinHttpCloseHandle(hS);
    return ok;
}

static bool AcIsLocalHost(const wchar_t* host) {
    return host && (!_wcsicmp(host, L"127.0.0.1") || !_wcsicmp(host, L"localhost") || !_wcsicmp(host, L"::1"));
}
static bool HttpPostBytes(const wchar_t* host, INTERNET_PORT port, const wchar_t* path,
                          const void* body, DWORD len, std::string& out) {
    // This POST carries the license build key (X-AC-Build). FORCE TLS for any real backend regardless
    // of the configured port, so the key is never sent in cleartext on the wire; only a localhost dev
    // endpoint may use plain HTTP. A misconfigured non-TLS backend just fails the handshake -> the
    // activation check is treated as unreachable -> fail-open (offline license stands), never a leak.
    bool secure = !AcIsLocalHost(host);
    return HttpPostCustom(host, port, path, secure,
                          L"application/octet-stream", nullptr, body, len, out, 4000, true);
}

static bool ParseEndpointUrl(const char* url, AcEndpoint& ep) {
    if (!url || !url[0]) return false;
    wchar_t wurl[1024];
    if (!MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, _countof(wurl))) return false;

    wchar_t host[256] = {};
    wchar_t path[512] = {};
    wchar_t extra[256] = {};
    URL_COMPONENTS uc; ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host; uc.dwHostNameLength = _countof(host);
    uc.lpszUrlPath = path;  uc.dwUrlPathLength = _countof(path);
    uc.lpszExtraInfo = extra; uc.dwExtraInfoLength = _countof(extra);
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) return false;
    if (uc.nScheme != INTERNET_SCHEME_HTTP && uc.nScheme != INTERNET_SCHEME_HTTPS) return false;
    if (!host[0]) return false;

    ep.secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    ep.port = uc.nPort ? uc.nPort : (ep.secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT);
    wcsncpy_s(ep.host, host, _TRUNCATE);
    if (path[0]) wcsncpy_s(ep.path, path, _TRUNCATE);
    else wcscpy_s(ep.path, L"/");
    if (extra[0] && wcslen(ep.path) + wcslen(extra) + 1 < _countof(ep.path)) wcscat_s(ep.path, extra);
    return true;
}

static ac_severity ParseSeverity(const char* s, ac_severity fallback) {
    if (!s) return fallback;
    if (!_stricmp(s, "info")) return AC_SEV_INFO;
    if (!_stricmp(s, "low")) return AC_SEV_LOW;
    if (!_stricmp(s, "medium") || !_stricmp(s, "med")) return AC_SEV_MED;
    if (!_stricmp(s, "high")) return AC_SEV_HIGH;
    if (!_stricmp(s, "critical") || !_stricmp(s, "crit")) return AC_SEV_CRIT;
    return fallback;
}

static AcHandleResponse ParseHandleResponse(const char* s) {
    if (!s || !*s) return AC_HANDLE_CORROBORATED;
    if (!_stricmp(s, "corroborated") || !_stricmp(s, "balanced") ||
        !_stricmp(s, "monitor") || !_stricmp(s, "report_only") || !_stricmp(s, "report")) {
        return AC_HANDLE_CORROBORATED;
    }
    if (!_stricmp(s, "terminate_write") || !_stricmp(s, "block_write") ||
        !_stricmp(s, "strict")) {
        return AC_HANDLE_TERMINATE_WRITE;
    }
    if (!_stricmp(s, "terminate_reader") || !_stricmp(s, "block_read_write") ||
        !_stricmp(s, "paranoid")) {
        return AC_HANDLE_TERMINATE_READER;
    }
    return AC_HANDLE_CORROBORATED;
}

static const char* HandleResponseName(AcHandleResponse r) {
    switch (r) {
        case AC_HANDLE_TERMINATE_WRITE: return "terminate_write";
        case AC_HANDLE_TERMINATE_READER: return "terminate_reader";
        case AC_HANDLE_CORROBORATED:
        default: return "corroborated";
    }
}

static AcSensorResponse ParseSensorResponse(const char* s, AcSensorResponse fallback) {
    if (!s || !*s) return fallback;
    if (!_stricmp(s, "report") || !_stricmp(s, "report_only") ||
        !_stricmp(s, "monitor") || !_stricmp(s, "off")) {
        return AC_RESP_REPORT;
    }
    if (!_stricmp(s, "corroborated") || !_stricmp(s, "corroborate") ||
        !_stricmp(s, "balanced")) {
        return AC_RESP_CORROBORATED;
    }
    if (!_stricmp(s, "terminate") || !_stricmp(s, "eject") ||
        !_stricmp(s, "block") || !_stricmp(s, "strict")) {
        return AC_RESP_TERMINATE;
    }
    return fallback;
}

static const char* SensorResponseName(AcSensorResponse r) {
    switch (r) {
        case AC_RESP_CORROBORATED: return "corroborated";
        case AC_RESP_TERMINATE: return "terminate";
        case AC_RESP_REPORT:
        default: return "report";
    }
}

static AcModuleResponse ParseModuleResponse(const char* s) {
    if (!s || !*s) return AC_MODULE_REPORT;
    if (!_stricmp(s, "report") || !_stricmp(s, "report_only") || !_stricmp(s, "monitor")) {
        return AC_MODULE_REPORT;
    }
    if (!_stricmp(s, "corroborated") || !_stricmp(s, "corroborate") || !_stricmp(s, "balanced")) {
        return AC_MODULE_CORROBORATED;
    }
    if (!_stricmp(s, "terminate_high") || !_stricmp(s, "terminate_known") ||
        !_stricmp(s, "known") || !_stricmp(s, "high")) {
        return AC_MODULE_TERMINATE_HIGH;
    }
    if (!_stricmp(s, "terminate_unsigned") || !_stricmp(s, "terminate") ||
        !_stricmp(s, "strict") || !_stricmp(s, "block_unsigned")) {
        return AC_MODULE_TERMINATE_UNSIGNED;
    }
    return AC_MODULE_REPORT;
}

static const char* ModuleResponseName(AcModuleResponse r) {
    switch (r) {
        case AC_MODULE_CORROBORATED: return "corroborated";
        case AC_MODULE_TERMINATE_HIGH: return "terminate_high";
        case AC_MODULE_TERMINATE_UNSIGNED: return "terminate_unsigned";
        case AC_MODULE_REPORT:
        default: return "report";
    }
}

static const char* SeverityName(ac_severity s) {
    switch (s) {
        case AC_SEV_INFO: return "info";
        case AC_SEV_LOW: return "low";
        case AC_SEV_MED: return "medium";
        case AC_SEV_HIGH: return "high";
        case AC_SEV_CRIT: return "critical";
        default: return "unknown";
    }
}

static const char* CategoryForSensor(const char* sensor) {
    if (!sensor) return "unknown";
    if (!strcmp(sensor, "Module")) return "injection";
    if (!strcmp(sensor, "CodeIntegrity")) return "hook_detection";
    if (!strcmp(sensor, "Handle")) return "handle_checks";
    if (!strcmp(sensor, "AntiDbg")) return "debugger";
    if (!strcmp(sensor, "License") || !strcmp(sensor, "SigUpdate") || !strcmp(sensor, "ACModule")) return "boot_state";
    if (!strcmp(sensor, "MemScan")) return "memory_integrity";
    if (!strcmp(sensor, "SelfProtect")) return "sdk_integrity";
    if (!strcmp(sensor, "ValueGuard")) return "protected_value";
    if (!strcmp(sensor, "AccessCheck")) return "access_check";
    if (!strcmp(sensor, "AimSnap") || !strcmp(sensor, "Triggerbot") || !strcmp(sensor, "Wallhack")) return "aim_behavior";
    if (!strcmp(sensor, "SaveGame")) return "savegame_integrity";
    if (!strcmp(sensor, "Enforce")) return "enforcement";
    return "unknown";
}

static bool TelemetryAllowsSensor(const AcTelemetryPolicy& p, const char* sensor) {
    const char* c = CategoryForSensor(sensor);
    if (!strcmp(c, "injection")) return p.eventInjection;
    if (!strcmp(c, "hook_detection")) return p.eventHooks;
    if (!strcmp(c, "handle_checks")) return p.eventHandles;
    if (!strcmp(c, "debugger")) return p.eventDebugger;
    if (!strcmp(c, "boot_state")) return p.eventBoot;
    if (!strcmp(c, "memory_integrity")) return p.eventMemory;
    if (!strcmp(c, "sdk_integrity")) return p.eventSdkIntegrity;
    if (!strcmp(c, "protected_value")) return p.eventProtectedValue;
    if (!strcmp(c, "access_check")) return p.eventAccessCheck;
    if (!strcmp(c, "aim_behavior")) return p.eventAimBehavior;
    if (!strcmp(c, "savegame_integrity")) return p.eventSaveGame;
    return true;
}

static void JsonStr(std::string& s, const char* key, const char* value, bool comma = true) {
    if (comma) s += ",";
    s += "\""; s += key; s += "\":\"";
    if (value) {
        for (const unsigned char* p = (const unsigned char*)value; *p; ++p) {
            unsigned char c = *p;
            if (c == '"' || c == '\\') { s += '\\'; s += (char)c; }
            else if (c == '\n') s += "\\n";
            else if (c == '\r') s += "\\r";
            else if (c == '\t') s += "\\t";
            else if (c < 32) { char b[7]; snprintf(b, sizeof(b), "\\u%04x", c); s += b; }
            else s += (char)c;
        }
    }
    s += "\"";
}

static void JsonNum(std::string& s, const char* key, unsigned long long value) {
    char b[64]; snprintf(b, sizeof(b), ",\"%s\":%llu", key, value); s += b;
}

static void JsonBool(std::string& s, const char* key, bool value) {
    s += ",\""; s += key; s += "\":"; s += value ? "true" : "false";
}

static void AppendContextJson(std::string& s, const AcRuntimeContext& ctx, const AcTelemetryPolicy* policy) {
    JsonStr(s, "game_id", ctx.gameId);
    JsonStr(s, "environment", ctx.environment);
    JsonStr(s, "identity_provider", ctx.identityProvider);
    if (!policy || policy->fieldPlayerId) JsonStr(s, "player_id", ctx.playerId);
    if (!policy || policy->fieldSessionId) JsonStr(s, "session_id", ctx.sessionId);
    if (!policy || policy->fieldPlatformUserId) JsonStr(s, "platform_user_id", ctx.platformUserId);
    if (!policy || policy->fieldGameBuild) JsonStr(s, "game_build", ctx.gameBuild);
}

static bool BuildAuthHeader(const char* name, const char* token, wchar_t* out, size_t outN) {
    if (!out || outN == 0) return false;
    out[0] = 0;
    if (!token || !token[0]) return false;
    char hn[64]; CopyClean(hn, sizeof(hn), (name && name[0]) ? name : "Authorization");
    for (size_t i = 0; hn[i]; ++i) {
        char c = hn[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
            strcpy_s(hn, "Authorization");
            break;
        }
    }
    char tv[256]; CopyClean(tv, sizeof(tv), token);
    wchar_t wh[80], wt[300];
    MultiByteToWideChar(CP_UTF8, 0, hn, -1, wh, _countof(wh));
    MultiByteToWideChar(CP_UTF8, 0, tv, -1, wt, _countof(wt));
    swprintf(out, outN, L"%s: %s\r\n", wh, wt);
    return true;
}

struct TelemetryJob {
    AcEndpoint ep;
    AcTelemetryPolicy policy;
    AcRuntimeContext ctx;
    char licenseId[17];
    int licenseTier;
    char sensor[64];
    char message[768];
    ac_severity severity;
    float confidence;
    unsigned long long detail;
    unsigned long long seq;
    wchar_t extraHeaders[512];
};
static volatile LONG g_telemetryInflight = 0;
static volatile LONG64 g_eventSeq = 0;

static DWORD WINAPI TelemetryThread(LPVOID p) {
    TelemetryJob* j = (TelemetryJob*)p;
    SYSTEMTIME st; GetSystemTime(&st);
    char ts[40]; snprintf(ts, sizeof(ts), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                          st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    char eid[80]; snprintf(eid, sizeof(eid), "%lu-%llu-%llu", GetCurrentProcessId(), GetTickCount64(), j->seq);

    std::string js = "{";
    JsonStr(js, "event_id", eid, false);
    JsonStr(js, "timestamp", ts);
    if (j->policy.fieldSdkVersion) JsonStr(js, "sdk_version", AC_Version());
    if (j->licenseId[0]) JsonStr(js, "license_id", j->licenseId);
    if (j->licenseTier > 0) JsonNum(js, "license_tier", (unsigned long long)j->licenseTier);
    AppendContextJson(js, j->ctx, &j->policy);
    JsonStr(js, "severity", SeverityName(j->severity));
    JsonStr(js, "category", CategoryForSensor(j->sensor));
    JsonStr(js, "sensor", j->sensor);
    JsonStr(js, "detection", j->sensor);
    char conf[32]; snprintf(conf, sizeof(conf), "%.2f", j->confidence);
    js += ",\"confidence\":"; js += conf;
    JsonNum(js, "detail", j->detail);
    if (j->policy.fieldActionTaken) JsonStr(js, "action_taken", "reported");
    if (j->policy.fieldServerObservedIp) JsonBool(js, "server_observed_ip", true);
    JsonBool(js, "client_sends_ip", false);
    JsonBool(js, "paths_redacted", j->policy.redactPaths);
    const char* msg = j->message;
    if (!j->policy.fieldProcessNames && !strcmp(CategoryForSensor(j->sensor), "handle_checks")) msg = "handle detection";
    JsonStr(js, "message", msg);
    js += "}";

    std::string resp;
    HttpPostCustom(j->ep.host, j->ep.port, j->ep.path, j->ep.secure,
                   L"application/json", j->extraHeaders,
                   js.data(), (DWORD)js.size(), resp, j->ep.timeoutMs);
    delete j;
    InterlockedDecrement(&g_telemetryInflight);
    return 0;
}

static void QueueTelemetry(const ac_detection* d) {
    if (!d) return;
    EnsureCoreInit();
    if (!AcRuntimeLicensed()) return;
    TelemetryJob* j = nullptr;
    EnterCriticalSection(&g_lock);
    if (!g_telemetryEndpoint.enabled || d->severity < g_tel.minSeverity || !TelemetryAllowsSensor(g_tel, d->sensor)) {
        LeaveCriticalSection(&g_lock);
        return;
    }
    if (InterlockedIncrement(&g_telemetryInflight) > 8) {
        InterlockedDecrement(&g_telemetryInflight);
        LeaveCriticalSection(&g_lock);
        return;
    }
    j = new(std::nothrow) TelemetryJob{};
    if (!j) {
        InterlockedDecrement(&g_telemetryInflight);
        LeaveCriticalSection(&g_lock);
        return;
    }
    j->ep = g_telemetryEndpoint;
    j->policy = g_tel;
    j->ctx = g_ctx;
    CopyClean(j->licenseId, sizeof(j->licenseId), g_licenseId);
    j->licenseTier = g_licTier;
    j->severity = d->severity;
    j->confidence = d->confidence;
    j->detail = d->detail;
    j->seq = (unsigned long long)InterlockedIncrement64(&g_eventSeq);
    CopyClean(j->sensor, sizeof(j->sensor), d->sensor);
    CopyClean(j->message, sizeof(j->message), d->message);
    BuildAuthHeader(g_tel.authHeader, g_tel.authToken, j->extraHeaders, _countof(j->extraHeaders));
    LeaveCriticalSection(&g_lock);

    HANDLE h = CreateThread(nullptr, 0, TelemetryThread, j, 0, nullptr);
    if (h) CloseHandle(h);
    else { delete j; InterlockedDecrement(&g_telemetryInflight); }
}

static bool JsonBoolValue(const char* json, const char* key, bool fallback) {
    if (!json || !key) return fallback;
    char pat[80]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = strstr(json, pat);
    if (!p) return fallback;
    p = strchr(p + strlen(pat), ':');
    if (!p) return fallback;
    while (*++p == ' ' || *p == '\t') {}
    if (!_strnicmp(p, "true", 4)) return true;
    if (!_strnicmp(p, "false", 5)) return false;
    if (*p == '1') return true;
    if (*p == '0') return false;
    return fallback;
}

static void JsonStringValue(const char* json, const char* key, char* out, size_t outN, const char* fallback) {
    CopyClean(out, outN, fallback ? fallback : "");
    if (!json || !key || !out || outN == 0) return;
    char pat[80]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = strstr(json, pat);
    if (!p) return;
    p = strchr(p + strlen(pat), ':');
    if (!p) return;
    while (*++p == ' ' || *p == '\t') {}
    if (*p != '"') return;
    ++p;
    size_t j = 0;
    while (*p && *p != '"' && j + 1 < outN) {
        if (*p == '\\' && p[1]) ++p;
        out[j++] = *p++;
    }
    out[j] = 0;
}

static bool RunAccessCheck(char* reason, size_t reasonN) {
    if (reason && reasonN) reason[0] = 0;
    EnsureCoreInit();
    if (!AcRuntimeLicensed()) {
        CopyClean(reason, reasonN, "access check skipped: SDK runtime is not licensed/armed");
        return true;
    }

    AcEndpoint ep;
    AcRuntimeContext ctx;
    AcTelemetryPolicy tel;
    wchar_t extraHeaders[512] = {};
    char failMode[24], provider[32], mode[32];

    EnterCriticalSection(&g_lock);
    if (!g_accessEndpoint.enabled) { LeaveCriticalSection(&g_lock); return true; }
    ep = g_accessEndpoint;
    ctx = g_ctx;
    tel = g_tel;
    CopyClean(failMode, sizeof(failMode), g_accessFailMode);
    CopyClean(provider, sizeof(provider), g_accessProvider);
    CopyClean(mode, sizeof(mode), g_accessMode);
    BuildAuthHeader(g_tel.authHeader, g_tel.authToken, extraHeaders, _countof(extraHeaders));
    LeaveCriticalSection(&g_lock);

    std::string js = "{";
    JsonStr(js, "request_type", "access_check", false);
    AppendContextJson(js, ctx, nullptr);
    JsonStr(js, "access_provider", provider);
    JsonStr(js, "mode", mode);
    JsonStr(js, "sdk_version", AC_Version());
    char licenseId[17] = ""; int licenseTier = 0;
    EnterCriticalSection(&g_lock);
    CopyClean(licenseId, sizeof(licenseId), g_licenseId);
    licenseTier = g_licTier;
    LeaveCriticalSection(&g_lock);
    if (licenseId[0]) JsonStr(js, "license_id", licenseId);
    if (licenseTier > 0) JsonNum(js, "license_tier", (unsigned long long)licenseTier);
    JsonBool(js, "client_side_only", true);
    js += "}";

    std::string resp;
    if (!HttpPostCustom(ep.host, ep.port, ep.path, ep.secure, L"application/json", extraHeaders,
                        js.data(), (DWORD)js.size(), resp, ep.timeoutMs)) {
        if (!_stricmp(failMode, "block")) {
            CopyClean(reason, reasonN, "access-check backend unreachable and fail_mode=block");
            return false;
        }
        CopyClean(reason, reasonN, "access-check backend unreachable; fail-open");
        return true;
    }

    bool allowed = JsonBoolValue(resp.c_str(), "allowed", true);
    if (!allowed) {
        char code[96]; JsonStringValue(resp.c_str(), "reason_code", code, sizeof(code), "active_ban");
        char msg[180]; snprintf(msg, sizeof(msg), "access denied by backend: %s", code);
        CopyClean(reason, reasonN, msg);
        return false;
    }
    CopyClean(reason, reasonN, "access allowed by backend");
    return true;
}

static DWORD WINAPI AccessRecheckThread(LPVOID) {
    for (;;) {
        int interval = 300;
        bool enabled = false;
        char mode[32], onSessionBan[32];

        EnterCriticalSection(&g_lock);
        enabled = g_accessEndpoint.enabled;
        interval = g_accessRecheckIntervalSec;
        CopyClean(mode, sizeof(mode), g_accessMode);
        CopyClean(onSessionBan, sizeof(onSessionBan), g_accessOnSessionBan);
        LeaveCriticalSection(&g_lock);

        if (!InterlockedCompareExchange(&g_running, 1, 1) || !enabled || _stricmp(mode, "startup_and_recheck")) {
            return 0;
        }

        if (interval < 30) interval = 30;
        if (interval > 3600) interval = 3600;
        for (int waited = 0; waited < interval; ++waited) {
            if (!InterlockedCompareExchange(&g_running, 1, 1)) return 0;
            Sleep(1000);
        }
        if (!InterlockedCompareExchange(&g_running, 1, 1)) return 0;

        char reason[220];
        bool allowed = RunAccessCheck(reason, sizeof(reason));
        ac_emit("AccessCheck", allowed ? AC_SEV_INFO : AC_SEV_CRIT, 1.0f,
                reason[0] ? reason : (allowed ? "access allowed" : "access denied"), 0);
        if (!allowed && !_stricmp(onSessionBan, "terminate")) {
            EjectHost("access denied by backend during session - terminating host process");
        }
    }
}

// ---------------------------------------------------------------------------
//  HARDENED Handle sensor
// ---------------------------------------------------------------------------
// Reduce a file path to its basename â€” used in detection messages so we don't leak full Windows
// paths (which contain the player's username) into the integrator's telemetry. PII minimization;
// the full path stays available internally for signature checks, just not in the emitted message.
static const char* AcBasename(const char* p) {
    const char* b = p ? p : "";
    for (const char* s = b; *s; s++) if (*s == '\\' || *s == '/') b = s + 1;
    return b;
}
struct HRep { DWORD pid; ULONG mask; };
static std::vector<HRep> g_hrep;
// report once per (pid, dangerous-bit-set); re-report only on new dangerous bits
static bool Handle_AlreadyReported(DWORD pid, ULONG dangerous) {
    for (auto& r : g_hrep) if (r.pid == pid) {
        if ((dangerous & ~r.mask) == 0) return true;
        r.mask |= dangerous; return false;
    }
    g_hrep.push_back({ pid, dangerous });
    return false;
}

// Our creator's PID (the launcher/parent that spawned us). A parent legitimately
// holds a full-access creation handle to its child for the child's whole lifetime
// (e.g. every UE bootstrap launcher -> game). Cached; queried once.
struct AC_PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};
static const ULONG AC_ProcessBasicInformation = 0;
static DWORD g_creatorPid = 0xFFFFFFFFu;   // 0xFFFFFFFF = not yet queried
static DWORD GetCreatorPid() {
    if (g_creatorPid != 0xFFFFFFFFu) return g_creatorPid;
    g_creatorPid = 0;
    if (g_NtQIP) {
        AC_PROCESS_BASIC_INFORMATION pbi; ZeroMemory(&pbi, sizeof(pbi));
        if (g_NtQIP(GetCurrentProcess(), AC_ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) == 0)
            g_creatorPid = (DWORD)pbi.InheritedFromUniqueProcessId;
    }
    return g_creatorPid;
}
// True if 'pid' started no later than we did. A genuine creator predates its
// child, so this guards the parent demotion against PID-reuse (the launcher
// exiting and its PID being recycled by an unrelated/malicious process).
static bool StartedAtOrBeforeUs(DWORD pid) {
    FILETIME ours{}, dummy{};
    if (!GetProcessTimes(GetCurrentProcess(), &ours, &dummy, &dummy, &dummy)) return false;
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return false;
    bool ok = false; FILETIME theirs{};
    if (GetProcessTimes(hp, &theirs, &dummy, &dummy, &dummy)) {
        ULARGE_INTEGER a, b;
        a.LowPart = theirs.dwLowDateTime; a.HighPart = theirs.dwHighDateTime;
        b.LowPart = ours.dwLowDateTime;   b.HighPart = ours.dwHighDateTime;
        ok = (a.QuadPart <= b.QuadPart);
    }
    CloseHandle(hp);
    return ok;
}

static void HandleSensor_Check() {
    if (!g_NtQSI) return;
    const DWORD ourPid = GetCurrentProcessId();

    // (1) A real handle to ourselves so we can find OUR kernel object pointer.
    HANDLE selfDup = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(),
                         &selfDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) return;

    // (2) Enumerate all system handles (grow on length mismatch; 64-bit sizing + hard cap
    //     so a hooked NtQSI cannot wrap sz to a tiny value).
    ULONG sz = 1u << 20; std::vector<BYTE> buf; NTSTATUS st = 0; ULONG ret = 0;
    for (int a = 0; a < 16; a++) {
        buf.resize(sz); ret = 0;
        st = g_NtQSI(SystemExtendedHandleInformation, buf.data(), sz, &ret);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            uint64_t want = (ret > sz) ? (uint64_t)ret + (1u << 16) : (uint64_t)sz * 2;
            if (want > (256ull << 20)) break;       // cap at 256 MB; avoids runaway + 32-bit wrap
            sz = (ULONG)want; continue;
        }
        break;
    }
    if (st < 0 || buf.size() < sizeof(AC_SYS_HANDLE_INFO_EX)) { CloseHandle(selfDup); return; }
    auto info = reinterpret_cast<AC_SYS_HANDLE_INFO_EX*>(buf.data());
    // Clamp the count to what the returned buffer can actually hold â€” never trust a
    // (possibly hooked) NtQSI's NumberOfHandles to bound the array walk (OOB-read fix).
    const SIZE_T cap = (buf.size() - offsetof(AC_SYS_HANDLE_INFO_EX, Handles)) / sizeof(AC_SYS_HANDLE_EX);
    ULONG_PTR n = info->NumberOfHandles;
    if ((SIZE_T)n > cap) n = cap;

    // (3) Our own process object pointer = Object of our self-handle entry.
    PVOID ourObject = nullptr;
    for (ULONG_PTR i = 0; i < n; i++) {
        const AC_SYS_HANDLE_EX& e = info->Handles[i];
        if ((DWORD)e.UniqueProcessId == ourPid && (HANDLE)e.HandleValue == selfDup) { ourObject = e.Object; break; }
    }
    if (!ourObject) { CloseHandle(selfDup); return; }

    // (4) Any handle whose Object == ourObject is a handle TO US (confirmed,
    //     no OpenProcess on the holder needed). Classify by signature only.
    for (ULONG_PTR i = 0; i < n; i++) {
        const AC_SYS_HANDLE_EX& e = info->Handles[i];
        if (e.Object != ourObject) continue;
        DWORD holder = (DWORD)e.UniqueProcessId;
        if (holder == ourPid || holder == 0 || holder == 4) continue;
        ULONG dangerous = e.GrantedAccess & AC_DANGEROUS_MASK;
        if (!dangerous) continue;
        if (Handle_AlreadyReported(holder, dangerous)) continue;

        // Classify the holder by SIGNATURE (catalog-aware), not name/parent.
        char disp[1024];
        HolderTrust t = ClassifyHolder(holder, disp, sizeof(disp));
        if (t == HT_TRUSTED) continue;   // signed -> benign (FP suppression)

        // FP-hardened severity by ACCESS CLASS (FP analysis): a read-only handle
        // is pervasive & benign (GPU/Steam/Discord overlays, AV/EDR, capture,
        // crash handlers, OS) -> LOW telemetry. Only WRITE/INJECT-class access is
        // the real memory-tamper signal. An UNINSPECTABLE holder is NOT proof of
        // anything (PPL AV / sibling AC / transient) -> at most MED, never CRIT.
        const ULONG WRITE_CLASS = PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE;
        bool hasWrite = (dangerous & WRITE_CLASS) != 0;
        const bool bReader = (!hasWrite && t == HT_UNTRUSTED);   // unsigned read-only holder (ESP shape)
        ac_severity sev; float conf; const char* tag;
        if (!hasWrite) {
            // Read-only handle. SIGNED holders were already suppressed above
            // (HT_TRUSTED -> continue), so we only get here for unsigned/uninspectable
            // ones. An UNSIGNED external process holding a read handle to us is
            // ESP/wallhack-shaped (it reads our memory to draw) -> MED telemetry, not
            // the near-ignored LOW. An uninspectable holder (PPL AV) could be reading
            // legitimately -> stays LOW (don't accuse what we can't verify).
            if (t == HT_UNTRUSTED) { sev = AC_SEV_MED; conf = 0.50f; tag = " [read-only, UNSIGNED holder - possible external reader/ESP]"; }
            else                   { sev = AC_SEV_LOW; conf = 0.30f; tag = " [read-only handle, uninspectable holder]"; }
        }
        else if (t == HT_UNKNOWN)    { sev = AC_SEV_MED;  conf = 0.55f; tag = " [write-class, uninspectable holder]"; }
        else if (holder == GetCreatorPid() && StartedAtOrBeforeUs(holder)) {
            // Our own creator/launcher holding a write-class creation handle is the
            // EXPECTED relationship (every UE bootstrap launcher does this). We do
            // NOT hard-trust the parent (that was spoofable Finding C) â€” an unsigned
            // launcher we can't verify is MED telemetry for the operator/server to
            // corroborate, not a HIGH auto-ban. A signed launcher is already
            // HT_TRUSTED above and suppressed entirely.
            sev = AC_SEV_MED;  conf = 0.50f; tag = " [write-class, creator/launcher - unsigned, unverified]";
        }
        else /* UNTRUSTED+write */   { sev = AC_SEV_HIGH; conf = 0.85f; tag = " [UNSIGNED write-class]"; }
        char msg[1200];
        snprintf(msg, sizeof(msg), "PID=%lu (%s) handle to us, access 0x%08lX%s",
                 holder, AcBasename(disp), (unsigned long)dangerous, tag);
        AcHandleResponse handleResponse = g_handleResponse;
        bool terminateWriteHandle = g_terminateOnTamper &&
            handleResponse >= AC_HANDLE_TERMINATE_WRITE &&
            hasWrite && t == HT_UNTRUSTED;
        bool terminateReaderHandle = bReader &&
            (g_ejectOnReader || (g_terminateOnTamper && handleResponse >= AC_HANDLE_TERMINATE_READER));
        ac_emit("Handle", sev, conf, msg, holder);
        // Optional aggressive policies. We terminate our own host process to deny the
        // session; user-mode AC cannot reliably close another process' handle in place.
        // A write/inject-class UNSIGNED handle is a strong single injector signal -> direct eject.
        if (terminateWriteHandle) EjectHost("ejecting unsigned external write/inject handle");
        // eject_on_reader is FP-prone (a read-only handle is a MED/0.50 signal that overlays and
        // capture tools also produce). Never hard-kill a paying customer on that ALONE: require a
        // second distinct sensor to have corroborated within the window, mirroring EjectEligible.
        if (terminateReaderHandle) {
            EnterCriticalSection(&g_lock);
            bool corroborated = CorrCorroborated("Handle");
            LeaveCriticalSection(&g_lock);
            if (corroborated) EjectHost("ejecting corroborated external reader (ESP/wallhack shape)");
            else ac_emit("Handle", AC_SEV_INFO, 1.0f,
                         "eject_on_reader held: single uncorroborated read-only holder (needs a 2nd signal)", holder);
        }
    }
    CloseHandle(selfDup);
}

// ---------------------------------------------------------------------------
//  Cooperative ValueGuard (per-session key; defeats the static-key shadow-sync)
// ---------------------------------------------------------------------------
struct Guard { volatile uint32_t* addr; uint32_t shadow; uint32_t pend; int pendCount; bool active; char label[48]; };
static std::vector<Guard> g_guards;
static bool g_enforceRestore = false;   // AC_FLAG_VALUEGUARD_RESTORE: block, don't just report

// FP/safety (FP backlog): never dereference a guarded address whose page is no
// longer committed/readable (the guarded UObject was GC'd/freed) -> no UAF/AV.
static bool PageReadable(const void* p) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT) return false;
    const DWORD R = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & R) && !(mbi.Protect & PAGE_GUARD);
}
// Writable check: the restore path WRITES the guarded address, so a read-only page
// (PAGE_READONLY/EXECUTE_READ â€” which PageReadable accepts) must NOT be written or the
// SDK access-violates the host game. Only RW protections qualify.
static bool PageWritable(const void* p) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT) return false;
    const DWORD W = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & W) && !(mbi.Protect & PAGE_GUARD);
}
// SEH-guarded 32-bit accessors: even after the page check, a guarded UObject can be freed/
// reprotected between the VirtualQuery and the access (TOCTOU) -> never let that fault the
// host game. No C++ objects here, so __try is permitted under /EHsc.
static bool TryReadU32(volatile uint32_t* a, uint32_t& out) {
    __try { out = *a; return true; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static bool TryWriteU32(volatile uint32_t* a, uint32_t v) {
    __try { *a = v; return true; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static Guard* FindGuard(volatile unsigned* addr) {
    for (auto& g : g_guards) if (g.addr == (volatile uint32_t*)addr) return &g;
    return nullptr;
}
static void ValueGuard_Check() {
    if (!AcRuntimeLicensed()) return;
    EnterCriticalSection(&g_lock);
    if (!g_valueGuardEnabled) { LeaveCriticalSection(&g_lock); return; }
    // Index-based loop re-evaluating size() each iteration. g_guards only ever GROWS
    // (AC_Unguard sets active=false, never erases), but AC_GuardU32 can push_back and
    // REALLOCATE during the unlocked ac_emit window below; a range-for reference/iterator
    // would then dangle -> UAF / arbitrary write. Indexing is safe (entries never shift).
    for (size_t i = 0; i < g_guards.size(); ++i) {
        Guard& g = g_guards[i];
        if (!g.active || !PageReadable((const void*)g.addr)) continue;
        uint32_t cur;
        if (!TryReadU32(g.addr, cur)) { g.active = false; continue; }          // page died -> retire, never fault
        if ((cur ^ g_sessionKey) == g.shadow) { g.pendCount = 0; continue; }   // matches -> fine
        // divergent: require the SAME value across 2 consecutive polls before reporting
        // (debounces torn reads + write/NoteLegit races -> FP fix).
        if (!(g.pendCount > 0 && g.pend == cur)) { g.pend = cur; g.pendCount = 1; continue; }
        if (++g.pendCount < 2) continue;
        uint32_t was = g.shadow ^ g_sessionKey;   // the last sanctioned value
        g.pendCount = 0;
        const char* tag;
        if (g_enforceRestore && PageWritable((const void*)g.addr) && TryWriteU32(g.addr, was)) {
            // ENFORCE: wrote the legit value back (godmode/infinite-ammo neutralised). Shadow
            // stays = was so the next poll matches; a re-write is caught + restored again.
            tag = " [BLOCKED: restored]";
        } else if (g_enforceRestore) {
            // restore requested but the page is read-only/dead -> DETECT, do not write (no AV).
            g.shadow = cur ^ g_sessionKey; tag = " [detected; restore skipped: non-writable]";
        } else {
            g.shadow = cur ^ g_sessionKey; tag = "";   // detect-only: re-baseline, report once
        }
        // snapshot everything ac_emit needs BEFORE unlocking; do NOT touch g afterward.
        char lbl[48]; memcpy(lbl, g.label, sizeof(lbl)); lbl[47] = 0;
        uintptr_t addrSnap = (uintptr_t)g.addr;
        bool terminateValueGuard = g_valueGuardTerminate;
        ac_severity valueGuardSeverity = g_valueGuardSeverity;
        char msg[220];
        snprintf(msg, sizeof(msg), "protected value '%s' changed out-of-band: %u -> %u (external write)%s", lbl, was, cur, tag);
        LeaveCriticalSection(&g_lock);
        ac_emit("ValueGuard", valueGuardSeverity, 1.0f, msg, (unsigned long long)addrSnap);
        if (terminateValueGuard) EjectHost("ejecting cheater: protected value tamper - terminating host process");
        EnterCriticalSection(&g_lock);   // g is stale now; the loop re-indexes on the next iteration
    }
    LeaveCriticalSection(&g_lock);
}

void AC_GuardU32(const char* name, volatile unsigned* addr) {
    if (!addr) return;
    EnsureCoreInit();   // safe even if the game registers a value before AC_Init runs
    EnterCriticalSection(&g_lock);
    Guard* g = FindGuard(addr);
    if (!g) {
        if (g_guards.size() >= g_valueGuardMaxTracked) { LeaveCriticalSection(&g_lock); return; }
        g_guards.push_back(Guard{}); g = &g_guards.back(); g->addr = (volatile uint32_t*)addr;
    }
    g->shadow = (*(volatile uint32_t*)addr) ^ g_sessionKey; g->active = true; g->label[0] = 0;
    if (name) { strncpy(g->label, name, sizeof(g->label) - 1); g->label[sizeof(g->label) - 1] = 0; }
    LeaveCriticalSection(&g_lock);
}
void AC_NoteLegit(volatile unsigned* addr) {
    EnsureCoreInit();
    EnterCriticalSection(&g_lock);
    Guard* g = FindGuard(addr);
    if (g && PageReadable((const void*)g->addr)) g->shadow = (*g->addr) ^ g_sessionKey;
    LeaveCriticalSection(&g_lock);
}
void AC_Unguard(volatile unsigned* addr) {
    EnsureCoreInit();
    EnterCriticalSection(&g_lock);
    Guard* g = FindGuard(addr);
    if (g) g->active = false;
    LeaveCriticalSection(&g_lock);
}
// Write-through setter: updates the value AND its shadow under one lock, so a
// legit write can never desync â€” eliminates the "forgot AC_NoteLegit" FP class.
void AC_SetGuardedU32(volatile unsigned* addr, unsigned val) {
    if (!addr) return;
    EnsureCoreInit();
    EnterCriticalSection(&g_lock);
    *addr = val;
    Guard* g = FindGuard(addr);
    if (g) { g->shadow = val ^ g_sessionKey; g->pendCount = 0; }
    LeaveCriticalSection(&g_lock);
}

void AC_GuardI32(const char* name, volatile int* addr) {
    AC_GuardU32(name, (volatile unsigned*)addr);
}

void AC_NoteLegitI32(volatile int* addr) {
    AC_NoteLegit((volatile unsigned*)addr);
}

void AC_UnguardI32(volatile int* addr) {
    AC_Unguard((volatile unsigned*)addr);
}

void AC_SetGuardedI32(volatile int* addr, int val) {
    AC_SetGuardedU32((volatile unsigned*)addr, (unsigned)val);
}

void AC_GuardFloat(const char* name, volatile float* addr) {
    AC_GuardU32(name, (volatile unsigned*)addr);
}

void AC_NoteLegitFloat(volatile float* addr) {
    AC_NoteLegit((volatile unsigned*)addr);
}

void AC_UnguardFloat(volatile float* addr) {
    AC_Unguard((volatile unsigned*)addr);
}

void AC_SetGuardedFloat(volatile float* addr, float val) {
    uint32_t bits = 0;
    memcpy(&bits, &val, sizeof(bits));
    AC_SetGuardedU32((volatile unsigned*)addr, bits);
}

static void AcSetContextField(char* dst, size_t dstN, const char* value) {
    EnsureCoreInit();
    EnterCriticalSection(&g_lock);
    CopyClean(dst, dstN, value);
    LeaveCriticalSection(&g_lock);
}

void AC_SetGameId(const char* value) {
    AcSetContextField(g_ctx.gameId, sizeof(g_ctx.gameId), value);
}

void AC_SetEnvironment(const char* value) {
    AcSetContextField(g_ctx.environment, sizeof(g_ctx.environment), value);
}

void AC_SetIdentityProvider(const char* value) {
    AcSetContextField(g_ctx.identityProvider, sizeof(g_ctx.identityProvider), value);
}

void AC_SetPlayerId(const char* value) {
    AcSetContextField(g_ctx.playerId, sizeof(g_ctx.playerId), value);
}

void AC_SetSessionId(const char* value) {
    AcSetContextField(g_ctx.sessionId, sizeof(g_ctx.sessionId), value);
}

void AC_SetPlatformUserId(const char* value) {
    AcSetContextField(g_ctx.platformUserId, sizeof(g_ctx.platformUserId), value);
}

void AC_SetGameBuild(const char* value) {
    AcSetContextField(g_ctx.gameBuild, sizeof(g_ctx.gameBuild), value);
}

void AC_SetTelemetryToken(const char* value) {
    EnsureCoreInit();
    EnterCriticalSection(&g_lock);
    CopyClean(g_tel.authToken, sizeof(g_tel.authToken), value);
    LeaveCriticalSection(&g_lock);
}

// Cooperative behavior hook (advisory). The game supplies the shot context; the SDK applies
// conservative built-in heuristics and emits advisory evidence for correlation.
void AC_ReportAim(float aimSpeed, float reactionMs, int hadLOS, int hit) {
    static int trig = 0;
#ifdef ACSDK_AIM_DEBUG
    // TEMPORARY liveness probe (build with /DACSDK_AIM_DEBUG): one INFO line per
    // shot so a live test can confirm the hook actually fires + the telemetry is
    // sane. Counter defeats the emit de-dup. Removed for the shipping artifact.
    { static int shotN = 0; char dbg[200];
      snprintf(dbg, sizeof(dbg), "shot #%d: aim=%.2f/ms react=%.0fms los=%d hit=%d",
               ++shotN, aimSpeed, reactionMs, hadLOS, hit);
      ac_emit("AimDebug", AC_SEV_INFO, 0.0f, dbg, 0); }
#endif
    if (hit && aimSpeed > 8.0f) {
        char m[160]; snprintf(m, sizeof(m), "aim snap: %.1f/ms onto a hit (super-human)", aimSpeed);
        ac_emit("AimSnap", AC_SEV_MED, 0.60f, m, 0);
    }
    if (hit && reactionMs > 0 && reactionMs < 60.0f) {
        if (++trig >= 3) { char m[160]; snprintf(m, sizeof(m), "trigger: fired %.0fms after acquire (x%d, sub-human)", reactionMs, trig); ac_emit("Triggerbot", AC_SEV_MED, 0.60f, m, 0); }
    } else if (reactionMs > 120.0f) trig = 0;
    if (hit && !hadLOS) ac_emit("Wallhack", AC_SEV_HIGH, 0.80f, "hit registered with no line of sight", 0);
}

// ---------------------------------------------------------------------------
//  MemScan sensor â€” manual-mapped executable images (closes the manual-map
//  blind spot that the loader-list Module sensor and start-address Thread
//  sensor both miss). LOW-FP signal: an executable region NOT backed by any
//  loaded module that carries a PE header (MZ + PE). JIT/script code has no PE
//  header, so JIT heaps do not false-positive (the classic private+exec trap).
// ---------------------------------------------------------------------------
struct ModRange { uintptr_t lo, hi; };
static std::vector<ModRange> SnapshotModules() {
    std::vector<ModRange> v;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (s == INVALID_HANDLE_VALUE) return v;
    MODULEENTRY32W me; me.dwSize = sizeof(me);
    if (Module32FirstW(s, &me)) do {
        uintptr_t b = (uintptr_t)me.modBaseAddr; v.push_back({ b, b + me.modBaseSize });
    } while (Module32NextW(s, &me));
    CloseHandle(s);
    return v;
}
static bool InModule(const std::vector<ModRange>& m, uintptr_t a) {
    for (auto& r : m) if (a >= r.lo && a < r.hi) return true;
    return false;
}
static std::vector<uintptr_t> g_mmReported;
static void MemScanSensor_Check() {
    std::vector<ModRange> mods = SnapshotModules();
    if (mods.empty()) return;   // snapshot failed -> do not flag (avoid a free-pass FP storm)
    const DWORD EXEC = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    MEMORY_BASIC_INFORMATION mbi;
    HANDLE self = GetCurrentProcess();
    for (uintptr_t a = 0; VirtualQuery((LPCVOID)a, &mbi, sizeof(mbi)) == sizeof(mbi); ) {
        uintptr_t base = (uintptr_t)mbi.BaseAddress, next = base + mbi.RegionSize;
        if (next <= a) break;
        // FP-hardened (FP analysis): only MEM_PRIVATE counts. Loader-mapped images
        // (CLR ReadyToRun, overlays, packed game code) are MEM_IMAGE/file-backed and
        // legitimately carry a PE header outside the Toolhelp list -> never a manual map.
        bool exec = (mbi.State == MEM_COMMIT) && (mbi.Protect & EXEC) &&
                    !(mbi.Protect & PAGE_GUARD) && (mbi.Type == MEM_PRIVATE);
        if (exec && !InModule(mods, base)) {
            // private executable region -> check for a *self-consistent* PE header
            uint8_t hdr[0x40]; SIZE_T got = 0; bool isPE = false;
            if (ReadProcessMemory(self, (LPCVOID)base, hdr, sizeof(hdr), &got) && got >= 0x40 &&
                hdr[0] == 'M' && hdr[1] == 'Z') {
                int32_t e = *(int32_t*)(hdr + 0x3C);
                if (e > 0 && (uintptr_t)e + 0x40 < mbi.RegionSize) {
                    uint8_t nt[0x40]; SIZE_T g2 = 0;
                    if (ReadProcessMemory(self, (LPCVOID)(base + e), nt, sizeof(nt), &g2) && g2 >= 0x1A &&
                        nt[0] == 'P' && nt[1] == 'E' && nt[2] == 0 && nt[3] == 0) {
                        uint16_t machine = *(uint16_t*)(nt + 4);     // COFF Machine
                        uint16_t magic   = *(uint16_t*)(nt + 0x18);  // Optional header Magic
                        bool okMachine = (machine == 0x8664 || machine == 0x014C || machine == 0xAA64);
                        bool okMagic   = (magic == 0x20B || magic == 0x10B);
                        isPE = okMachine && okMagic;                 // reject coincidental MZ..PE
                    }
                }
            }
            bool already = false; for (auto x : g_mmReported) if (x == base) { already = true; break; }
            if (isPE && !already) {
                g_mmReported.push_back(base);
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "manual-mapped PE image at 0x%llX (%llu KB, executable, not backed by any loaded module)",
                         (unsigned long long)base, (unsigned long long)(mbi.RegionSize / 1024));
                ac_emit("MemScan", AC_SEV_HIGH, 0.90f, msg, (unsigned long long)base);
            }
            // RWX-without-PE is a JIT/shellcode grey zone (FP-prone) -> deliberately
            // not flagged here; reserved for a configurable lower-tier signal.
        }
        a = next;
    }
}

// ---------------------------------------------------------------------------
//  Signed cheat-hash deny-list storage (Step 3). The data + lookup live here so the
//  Module sensor below can consult them; the SIGNED file is loaded/verified later
//  (AcLoadSignatures, after AcVerifySigned is defined). See that section for the
//  security model â€” the list can only ADD detections, never weaken the built-ins.
// ---------------------------------------------------------------------------
struct SigEntry { BYTE hash[32]; char label[48]; };
static std::vector<SigEntry> g_sigDb;
static long long g_sigEpoch = 0;
static bool AcHexToBytes(const char* hex, BYTE* out, size_t n) {
    auto hv = [](char c) -> int { return (c <= '9') ? c - '0' : (c | 32) - 'a' + 10; };
    for (size_t i = 0; i < n; i++) {
        char a = hex[i * 2], b = hex[i * 2 + 1];
        if (!isxdigit((unsigned char)a) || !isxdigit((unsigned char)b)) return false;
        out[i] = (BYTE)((hv(a) << 4) | hv(b));
    }
    return true;
}
// SHA-256 a file by streaming it (bounded buffer). Used to match a loaded module against g_sigDb.
static bool AcSha256File(const wchar_t* path, BYTE out[32]) {
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) { CloseHandle(hf); return false; }
    BCRYPT_HASH_HANDLE hH = nullptr; bool ok = false;
    if (BCryptCreateHash(hAlg, &hH, nullptr, 0, nullptr, 0, 0) == 0) {
        BYTE buf[65536]; DWORD rd = 0; ok = true;
        while (ReadFile(hf, buf, sizeof(buf), &rd, nullptr) && rd > 0)
            if (BCryptHashData(hH, buf, rd, 0) != 0) { ok = false; break; }
        if (ok && BCryptFinishHash(hH, out, 32, 0) != 0) ok = false;
        BCryptDestroyHash(hH);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0); CloseHandle(hf);
    return ok;
}
static const SigEntry* AcMatchSig(const BYTE h[32]) {
    for (auto& e : g_sigDb) if (memcmp(e.hash, h, 32) == 0) return &e;
    return nullptr;
}

// ---------------------------------------------------------------------------
//  Module sensor â€” newly-loaded UNSIGNED modules (LoadLibrary-injected DLLs).
//  Replaces the spoofable trusted-path-prefix policy with catalog-aware
//  signature verification: a module that appears after the startup baseline and
//  is not validly signed is a likely DLL injection. Signed on-demand system
//  DLLs are folded in silently (low FP). Pairs with MemScan (manual maps).
// ---------------------------------------------------------------------------
static std::vector<uintptr_t> g_modBaseline;
static ULONGLONG g_acStartTick = 0;
static const ULONGLONG AC_MODULE_WARMUP_MS = 4000;   // legit lazy/plugin DLLs cluster early
static void ModuleSensor_Refresh(bool initial) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (s == INVALID_HANDLE_VALUE) return;
    bool warmup = (GetTickCount64() - g_acStartTick) < AC_MODULE_WARMUP_MS;
    MODULEENTRY32W me; me.dwSize = sizeof(me);
    if (Module32FirstW(s, &me)) do {
        uintptr_t b = (uintptr_t)me.modBaseAddr;
        bool known = false; for (auto x : g_modBaseline) if (x == b) { known = true; break; }
        if (known) continue;
        g_modBaseline.push_back(b);
        if (initial) continue;                       // startup baseline: trust + skip hashing cost
        // Signed deny-list (Step 3): a known-cheat hash is HIGH regardless of Authenticode and
        // even within the warm-up window (a known cheat is never a warm-up false positive).
        if (!g_sigDb.empty()) {
            BYTE h[32];
            if (AcSha256File(me.szExePath, h)) {
                const SigEntry* hit = AcMatchSig(h);
                if (hit) {
                    char hp[MAX_PATH]; WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, hp, sizeof(hp), nullptr, nullptr); hp[sizeof(hp) - 1] = 0;
                    char msg[520]; snprintf(msg, sizeof(msg), "KNOWN CHEAT signature '%s' loaded: %s", hit->label, AcBasename(hp));
                    ac_emit("Module", AC_SEV_HIGH, 0.95f, msg, (unsigned long long)b);
                    continue;
                }
            }
        }
        if (warmup) continue;                        // warm-up window = silent baseline for the unsigned heuristic (FP fix)
        SigVerdict v = ClassifyFileSig(me.szExePath);
        if (v != SIG_UNTRUSTED) continue;            // trusted OR verify-error (don't accuse) -> skip (FP fix)
        char apath[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, apath, sizeof(apath), nullptr, nullptr); apath[sizeof(apath) - 1] = 0;
        char msg[600];
        snprintf(msg, sizeof(msg), "newly-loaded UNSIGNED module: %s (possible DLL injection)", AcBasename(apath));
        // single unsigned module = MED corroborating signal, not a standalone ban (FP analysis)
        ac_emit("Module", AC_SEV_MED, 0.55f, msg, (unsigned long long)b);
        if (g_terminateOnTamper && g_moduleResponse == AC_MODULE_TERMINATE_UNSIGNED)
            EjectHost("ejecting unsigned injected module");
    } while (Module32NextW(s, &me));
    CloseHandle(s);
}

// ---------------------------------------------------------------------------
//  AntiDbg sensor â€” syscall-level debugger detection. Queries the kernel debug
//  state via NtQueryInformationProcess (DebugPort/DebugObjectHandle/DebugFlags)
//  which is a stronger signal than PEB.BeingDebugged (the latter is trivially
//  zeroed by ScyllaHide-class plugins). Very low FP: debug state is binary, a
//  non-debugged process returns clean values. Report-once.
// ---------------------------------------------------------------------------
static bool    g_antidbgLatched = false;
static const ULONG ProcessDebugPort = 7, ProcessDebugObjectHandle = 30, ProcessDebugFlags = 31;
static void AntiDbgSensor_Check() {
    if (g_antidbgLatched) return;
    HANDLE self = GetCurrentProcess();
    const char* reason = nullptr;
    if (IsDebuggerPresent()) reason = "PEB.BeingDebugged set";
    if (!reason && g_NtQIP) {
        ULONG_PTR port = 0;
        if (g_NtQIP(self, ProcessDebugPort, &port, sizeof(port), nullptr) == 0 && port != 0) reason = "ProcessDebugPort != 0";
    }
    if (!reason && g_NtQIP) {
        HANDLE dobj = nullptr;
        if (g_NtQIP(self, ProcessDebugObjectHandle, &dobj, sizeof(dobj), nullptr) == 0 && dobj) { reason = "ProcessDebugObjectHandle present"; CloseHandle(dobj); }
    }
    if (!reason && g_NtQIP) {
        ULONG flags = 1;
        if (g_NtQIP(self, ProcessDebugFlags, &flags, sizeof(flags), nullptr) == 0 && flags == 0) reason = "ProcessDebugFlags == 0 (being debugged)";
    }
    if (reason) {
        g_antidbgLatched = true;
        char msg[200]; snprintf(msg, sizeof(msg), "debugger attached: %s", reason);
        ac_emit("AntiDbg", AC_SEV_HIGH, 0.90f, msg, 0);
    }
}

// ---------------------------------------------------------------------------
//  CodeIntegrity sensor â€” IAT hooks (an import thunk resolving OUTSIDE all
//  loaded modules = a trampoline) and inline hooks on sensitive ntdll/
//  kernelbase prologues. FP-aware: a hook whose destination is inside a SIGNED
//  loaded module is likely a security product (EDR/AV) -> LOW; a hook into
//  private/unbacked memory is the cheat signal -> HIGH. Prologues are baselined
//  at init, so pre-existing EDR hooks are NOT flagged (only new ones).
// ---------------------------------------------------------------------------
struct Prologue { uint8_t* fn; uint8_t base[16]; const char* name; bool reported; };
static std::vector<Prologue> g_prologues;
static std::vector<uintptr_t> g_iatReported;

static void CodeIntegrity_Init() {
    const wchar_t* mods[] = { L"ntdll.dll", L"kernelbase.dll", nullptr };
    const char* fns[] = { "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory",
        "NtAllocateVirtualMemory", "NtCreateThreadEx", "NtMapViewOfSection", "NtQueueApcThread",
        "NtGetContextThread", "NtSetContextThread", "NtQueryVirtualMemory", "NtOpenProcess", "LdrLoadDll", nullptr };
    for (int m = 0; mods[m]; m++) {
        HMODULE h = GetModuleHandleW(mods[m]); if (!h) continue;
        for (int i = 0; fns[i]; i++) {
            uint8_t* f = (uint8_t*)(void*)GetProcAddress(h, fns[i]);
            if (f) { Prologue p; p.fn = f; p.name = fns[i]; p.reported = false; memcpy(p.base, f, 16); g_prologues.push_back(p); }
        }
    }
}
// Parses a hook trampoline whose bytes are ATTACKER-CONTROLLED (a cheat overwrote
// this prologue). SEH-guarded so a malformed/unmapped target cannot fault the host
// game, and the jmp-[rip] form's pointer slot is validated before deref.
static uintptr_t ParseJmpDest(const uint8_t* p) {
    __try {
        if (p[0] == 0xE9) return (uintptr_t)(p + 5 + *(int32_t*)(p + 1));                       // jmp rel32
        if (p[0] == 0xFF && p[1] == 0x25) {                                                     // jmp [rip+d32]
            void** q = (void**)(p + 6 + *(int32_t*)(p + 2));
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(q, &mbi, sizeof(mbi)) != sizeof(mbi) || mbi.State != MEM_COMMIT ||
                (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return 0;
            return (uintptr_t)*q;
        }
        if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) return *(uintptr_t*)(p + 2);             // mov rax,imm64; jmp rax
        if (p[0] == 0x68 && p[5] == 0xC3) return (uintptr_t)(uint32_t) * (uint32_t*)(p + 1);                          // push imm32; ret
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
// SEH-isolated raw walk of our own (possibly cheat-tampered) import table. Collects up to
// 'cap' thunks whose target resolves outside every loaded module. Every RVA is bounded
// against SizeOfImage so a corrupted import descriptor cannot walk off the mapped image,
// and the SEH backstops any residual fault. No C++ objects -> __try allowed under /EHsc.
static int CollectIatHooks(const ModRange* mods, size_t nmods, uintptr_t* outThunk, uintptr_t* outFn, int cap) {
    int cnt = 0;
    __try {
        uint8_t* base = (uint8_t*)GetModuleHandleW(nullptr);
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        IMAGE_NT_HEADERS* nth = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nth->Signature != IMAGE_NT_SIGNATURE) return 0;
        const DWORD     imgSize = nth->OptionalHeader.SizeOfImage;
        const uintptr_t imgEnd  = (uintptr_t)base + imgSize;
        IMAGE_DATA_DIRECTORY dir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.VirtualAddress || dir.VirtualAddress >= imgSize) return 0;
        IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
        const DWORD maxDesc = dir.Size / (DWORD)sizeof(IMAGE_IMPORT_DESCRIPTOR);
        for (DWORD di = 0; di < maxDesc && desc[di].Name && cnt < cap; di++) {
            DWORD ftRva = desc[di].FirstThunk;
            if (!ftRva || ftRva >= imgSize) continue;
            for (IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(base + ftRva);
                 (uintptr_t)thunk + sizeof(IMAGE_THUNK_DATA) <= imgEnd && thunk->u1.Function && cnt < cap; thunk++) {
                uintptr_t fn = (uintptr_t)thunk->u1.Function;
                bool in = false; for (size_t m = 0; m < nmods; m++) if (fn >= mods[m].lo && fn < mods[m].hi) { in = true; break; }
                if (in) continue;
                outThunk[cnt] = (uintptr_t)thunk; outFn[cnt] = fn; cnt++;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return cnt; }
    return cnt;
}

// SEH-guarded prologue compare: CodeIntegrity inspects code a cheat may have patched and
// then unmapped; a faulting read must not crash the host game. A fault -> treat as
// "unchanged" (skip) rather than propagate the access violation.
static bool PrologueChanged(const uint8_t* fn, const uint8_t* base16) {
    __try { return memcmp(fn, base16, 16) != 0; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static void CodeIntegrity_Check() {
    std::vector<ModRange> mods = SnapshotModules();
    if (mods.empty()) return;
    // (1) inline hooks on baselined prologues
    for (auto& p : g_prologues) {
        if (p.reported || !PrologueChanged(p.fn, p.base)) continue;
        uintptr_t dest = ParseJmpDest(p.fn);
        bool inMod = dest && InModule(mods, dest);
        p.reported = true;
        char msg[256];
        if (inMod) { snprintf(msg, sizeof(msg), "inline hook on %s -> loaded module 0x%llX (likely security product)", p.name, (unsigned long long)dest);
                     ac_emit("CodeIntegrity", AC_SEV_LOW, 0.40f, msg, dest); }
        else       { snprintf(msg, sizeof(msg), "inline hook on %s -> unbacked memory 0x%llX (code patch)", p.name, (unsigned long long)dest);
                     ac_emit("CodeIntegrity", AC_SEV_HIGH, 0.85f, msg, dest); }
    }
    // (2) IAT hooks: our own import thunks resolving outside all modules (SEH-bounded walk)
    uintptr_t hookThunk[64], hookFn[64];
    int nh = CollectIatHooks(mods.data(), mods.size(), hookThunk, hookFn, 64);
    for (int k = 0; k < nh; k++) {
        bool already = false; for (auto x : g_iatReported) if (x == hookThunk[k]) { already = true; break; }
        if (already) continue;
        g_iatReported.push_back(hookThunk[k]);
        char msg[256]; snprintf(msg, sizeof(msg), "IAT hook: import thunk -> unbacked memory 0x%llX", (unsigned long long)hookFn[k]);
        ac_emit("CodeIntegrity", AC_SEV_HIGH, 0.85f, msg, hookFn[k]);
    }
}

// ---------------------------------------------------------------------------
//  Self-protection: mutual-heartbeat watchdog. The scan thread and a watchdog
//  thread each beat a counter and verify the other advances. Suspending or
//  killing the AC thread (the classic silencing attack) stalls its beat, and
//  the surviving thread reports it. A cheat must freeze BOTH within ~2 intervals.
// ---------------------------------------------------------------------------
static volatile LONG64 g_scanBeat = 0, g_watchBeat = 0;
static HANDLE          g_watchThread = nullptr;
static volatile LONG   g_testStall = 0;   // self-test hook only

static DWORD WINAPI WatchdogThread(LPVOID) {
    int iv = g_cfg.scan_interval_ms ? (int)g_cfg.scan_interval_ms : 750;
    LONG64 lastScan = g_scanBeat; int miss = 0;
    while (InterlockedCompareExchange(&g_running, 1, 1)) {
        Sleep(iv);
        InterlockedIncrement64((volatile LONG64*)&g_watchBeat);
        if (!InterlockedCompareExchange(&g_running, 1, 1)) break;
        if (g_scanBeat == lastScan) {
            if (++miss >= 2) { ac_emit("SelfProtect", AC_SEV_HIGH, 0.90f, "AC scan thread stalled/suspended (anti-cheat tamper)", 0); miss = 0; }
        } else { miss = 0; lastScan = g_scanBeat; }
    }
    return 0;
}

// ---------------------------------------------------------------------------
//  License gate (Step 2) â€” OFFLINE RSA-2048 PKCS#1 v1.5 / SHA-256 verification
//  via BCrypt against an EMBEDDED public key. No phone-home: a customer's build
//  validates its own license locally, so it works air-gapped / on a LAN tournament
//  PC. A license is a signed token  base64(payload) "." base64(signature)  whose
//  payload is a ";"-delimited "k=v" string (v,cid,cust,title,tier,bk,iss,exp,feat)
//  â€” the same format the Python issuer (issue.py) emits. The SDK refuses to arm
//  sensors unless the signature verifies AND the license is unexpired (fail-closed),
//  but it NEVER crashes the host on an unlicensed start.
//
//  Embedded public key (from sdk_pubkey.txt; modulus big-endian, e = 65537). If
//  you rotate the issuer keypair, regenerate this array â€” old licenses stop
//  verifying, which is the intended kill-switch.
// ---------------------------------------------------------------------------
static const unsigned char AC_PUB_N[256] = {
    0xc7, 0x15, 0x8b, 0x3e, 0x46, 0x1f, 0x2c, 0xcb, 0x26, 0x0e, 0x32, 0xac,
    0xaa, 0xd7, 0xe6, 0x49, 0x37, 0x95, 0xfd, 0xf9, 0x76, 0x59, 0x53, 0x15,
    0xc1, 0xdd, 0x5e, 0x6a, 0xc2, 0x6d, 0x6b, 0xac, 0x38, 0xaf, 0xf1, 0xe7,
    0x69, 0xdf, 0xfd, 0x82, 0x89, 0x15, 0xab, 0xa1, 0x59, 0x31, 0x2b, 0x3e,
    0xab, 0x86, 0x57, 0x96, 0x2d, 0xe8, 0xf5, 0x07, 0x0a, 0xbd, 0xc9, 0x6d,
    0x00, 0x29, 0xa2, 0xc3, 0x9e, 0xf3, 0x1d, 0xa1, 0x98, 0xe6, 0xc3, 0x80,
    0x59, 0xc6, 0x33, 0x3a, 0xa2, 0x4e, 0x7b, 0x80, 0xa3, 0x41, 0x25, 0xb5,
    0xda, 0xd9, 0x4d, 0xe0, 0x46, 0x77, 0x8d, 0xaf, 0xde, 0x02, 0xa3, 0x06,
    0x46, 0xad, 0x82, 0x8c, 0x82, 0x09, 0x9f, 0xd0, 0x9e, 0xae, 0xfe, 0x5f,
    0x4e, 0xa3, 0x8b, 0xdc, 0x8c, 0xf0, 0x75, 0x59, 0x37, 0xde, 0xc8, 0x92,
    0xf3, 0x94, 0x0a, 0xa7, 0xc5, 0x15, 0x20, 0x09, 0x3f, 0x23, 0x3d, 0xa2,
    0x3e, 0xe7, 0x12, 0x06, 0xd1, 0x1b, 0x0b, 0x5b, 0x97, 0x76, 0x95, 0x97,
    0x64, 0xca, 0xaa, 0x40, 0x9e, 0xb4, 0xd3, 0xbe, 0x93, 0x7b, 0xb6, 0xc0,
    0x51, 0x2f, 0xc3, 0xf3, 0xf2, 0x8e, 0x39, 0xfe, 0xa7, 0xcc, 0x11, 0x74,
    0x03, 0x29, 0xc9, 0x0a, 0x12, 0x51, 0x73, 0x96, 0xd7, 0xd7, 0xad, 0x31,
    0x90, 0x4e, 0x78, 0x85, 0xd8, 0x6f, 0x6a, 0xcd, 0xa5, 0xce, 0x6b, 0x83,
    0xe5, 0x76, 0x38, 0x43, 0xf8, 0xb1, 0x15, 0xc2, 0xc6, 0x00, 0xee, 0xe8,
    0x1a, 0xfb, 0xf0, 0x97, 0xad, 0x95, 0x0b, 0x90, 0x23, 0xce, 0x73, 0x19,
    0x57, 0xfb, 0x67, 0xd8, 0xdd, 0x25, 0x89, 0xd8, 0x90, 0xcc, 0x3d, 0xf5,
    0x31, 0xe4, 0xda, 0x9e, 0xb4, 0xf0, 0xda, 0xea, 0x95, 0x46, 0xad, 0x5e,
    0xd2, 0x89, 0xbc, 0xe7, 0x83, 0xda, 0xbc, 0xf4, 0xbf, 0xf4, 0x0b, 0xfd,
    0x63, 0x58, 0x4d, 0xdd,
};
static const unsigned char AC_PUB_E[3] = { 0x01, 0x00, 0x01 };  // 65537 (shared exponent)

//  Embedded VERDICT public key (from ac_verdict_array.txt; modulus big-endian, e = 65537). SEPARATE
//  from the license key: the backend signs online activation/revocation verdicts with the matching
//  verdict PRIVATE key so a "revoked"/"expired" deny is tamper-evident. A forged/unsigned reply is
//  ignored (fail-open) — a network attacker cannot forge a deny to grief a paying customer, and the
//  high-value license key never has to touch the always-on activation backend. Rotate together with
//  korvayne_verdict_private.pem.
static const unsigned char AC_VERDICT_N[256] = {
    0xd5, 0x65, 0xff, 0xfe, 0xc0, 0xb0, 0x07, 0x8b, 0x84, 0x11, 0x07, 0xb3,
    0x89, 0x9a, 0xe2, 0x36, 0xb0, 0x5a, 0x6f, 0x40, 0x9e, 0x0b, 0x89, 0xfd,
    0x52, 0x6f, 0xf3, 0xa8, 0x05, 0xc8, 0x95, 0xeb, 0xc5, 0xb4, 0x0f, 0x0f,
    0xd5, 0x4e, 0x41, 0x11, 0x90, 0xba, 0xf5, 0x79, 0x7d, 0xa3, 0xf9, 0x9e,
    0xa5, 0x03, 0xf9, 0x4b, 0x0c, 0x43, 0x14, 0xf5, 0x5b, 0xbb, 0x45, 0xa8,
    0x26, 0xca, 0x27, 0x88, 0x94, 0xcb, 0x63, 0x29, 0xd7, 0x1f, 0x85, 0x4a,
    0x5d, 0x2c, 0x09, 0x54, 0xa1, 0x41, 0x3d, 0xd2, 0x52, 0x3e, 0xef, 0x21,
    0x23, 0x9b, 0x75, 0xb9, 0x2c, 0x60, 0xb9, 0xdc, 0xbf, 0x99, 0x04, 0x77,
    0x7f, 0x13, 0xe2, 0xdb, 0x78, 0xf4, 0xd5, 0x50, 0x51, 0x84, 0xcd, 0xe1,
    0x1e, 0x43, 0x40, 0x82, 0x1e, 0x8b, 0x64, 0xe2, 0xe5, 0xed, 0x71, 0xd9,
    0x82, 0x97, 0x66, 0x5c, 0xc3, 0x73, 0x46, 0x4b, 0x03, 0x13, 0xd6, 0xdc,
    0x0c, 0x26, 0xce, 0xc8, 0xd2, 0x41, 0xbc, 0x58, 0xf9, 0x60, 0x9e, 0x6b,
    0x86, 0xc9, 0x5f, 0x8f, 0x46, 0x22, 0xd8, 0x5c, 0x97, 0x83, 0x03, 0x9f,
    0x86, 0x19, 0x6b, 0x08, 0x1f, 0x24, 0x1a, 0x6f, 0xc4, 0xd8, 0x9e, 0xd0,
    0xb7, 0x3f, 0x79, 0x61, 0x40, 0x6f, 0xeb, 0x3d, 0xb4, 0x34, 0x3f, 0x32,
    0x8a, 0xae, 0xf8, 0x85, 0x60, 0x7d, 0xe0, 0xbf, 0x1a, 0x66, 0x5d, 0xaa,
    0x4b, 0x64, 0x7d, 0x3b, 0x01, 0x51, 0x3b, 0xcc, 0x23, 0xfa, 0x09, 0x31,
    0xda, 0x0d, 0x27, 0x3f, 0xca, 0x6d, 0xea, 0xbd, 0x13, 0x81, 0x99, 0x5a,
    0x1d, 0x48, 0x2c, 0x58, 0x56, 0xe7, 0x83, 0xd8, 0xc2, 0xbb, 0xc6, 0xe4,
    0xb6, 0x9c, 0xfb, 0x7a, 0xe9, 0x22, 0x42, 0xf6, 0xe7, 0x84, 0xbc, 0xb1,
    0x4b, 0x2b, 0x2a, 0xb0, 0x26, 0xa3, 0x12, 0xcf, 0xae, 0xde, 0x3c, 0x44,
    0x07, 0x40, 0xf9, 0x63,
};

struct AcLicense {
    bool      sigOk;        // signature verified against the embedded key
    bool      expired;      // exp <= now
    bool      malformed;    // signed but missing required commercial fields
    bool      valid;        // sigOk && !expired && !malformed
    int       tier;
    long long exp;
    char      title[64];
    char      customer[96];
    char      buildKey[80];
    char      features[128];
};

static bool AcB64Decode(const char* s, size_t n, std::vector<BYTE>& out) {
    DWORD cb = 0;
    if (!CryptStringToBinaryA(s, (DWORD)n, CRYPT_STRING_BASE64, nullptr, &cb, nullptr, nullptr) || !cb) return false;
    out.resize(cb);
    if (!CryptStringToBinaryA(s, (DWORD)n, CRYPT_STRING_BASE64, out.data(), &cb, nullptr, nullptr)) return false;
    out.resize(cb);
    return true;
}
static bool AcSha256(const BYTE* data, DWORD len, BYTE out[32]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
    BCRYPT_HASH_HANDLE hH = nullptr; bool ok = false;
    if (BCryptCreateHash(hAlg, &hH, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(hH, (PUCHAR)data, len, 0) == 0 && BCryptFinishHash(hH, out, 32, 0) == 0) ok = true;
        BCryptDestroyHash(hH);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}
static void AcShortSha256Hex(const char* text, char out[17]) {
    if (!out) return;
    out[0] = 0;
    if (!text || !text[0]) return;
    BYTE h[32];
    if (!AcSha256((const BYTE*)text, (DWORD)strlen(text), h)) return;
    for (int i = 0; i < 8; ++i) snprintf(out + i * 2, 3, "%02x", h[i]);
    out[16] = 0;
}

static bool AcHmacSha256(const BYTE* key, DWORD keyLen, const BYTE* data, DWORD len, BYTE out[32]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return false;
    BCRYPT_HASH_HANDLE hH = nullptr; bool ok = false;
    if (BCryptCreateHash(hAlg, &hH, nullptr, 0, (PUCHAR)key, keyLen, 0) == 0) {
        if (BCryptHashData(hH, (PUCHAR)data, len, 0) == 0 && BCryptFinishHash(hH, out, 32, 0) == 0) ok = true;
        BCryptDestroyHash(hH);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static void AcAppend(std::vector<BYTE>& v, const void* p, size_t n) {
    if (!p || n == 0) return;
    const BYTE* b = (const BYTE*)p;
    v.insert(v.end(), b, b + n);
}

static void AcPutU16(BYTE* p, uint16_t v) {
    p[0] = (BYTE)(v & 0xffu); p[1] = (BYTE)((v >> 8) & 0xffu);
}

static void AcPutU32(BYTE* p, uint32_t v) {
    p[0] = (BYTE)(v & 0xffu); p[1] = (BYTE)((v >> 8) & 0xffu);
    p[2] = (BYTE)((v >> 16) & 0xffu); p[3] = (BYTE)((v >> 24) & 0xffu);
}

static uint16_t AcGetU16(const BYTE* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t AcGetU32(const BYTE* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static bool AcConstEq32(const BYTE a[32], const BYTE b[32]) {
    BYTE x = 0;
    for (int i = 0; i < 32; ++i) x |= (BYTE)(a[i] ^ b[i]);
    return x == 0;
}

static bool AcRandomBytes(BYTE* out, DWORD n) {
    return out && BCryptGenRandom(nullptr, out, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

static bool AcSaveDeriveKey(BYTE out[32]) {
    char buildKey[80] = {};
    char title[64] = {};
    EnterCriticalSection(&g_lock);
    CopyClean(buildKey, sizeof(buildKey), g_buildKey);
    CopyClean(title, sizeof(title), g_licenseTitle);
    LeaveCriticalSection(&g_lock);
    if (!buildKey[0]) return false;
    std::string material = "korvayne-save-key-v1|";
    material += buildKey;
    material += "|title=";
    material += title;
    return AcSha256((const BYTE*)material.data(), (DWORD)material.size(), out);
}

static bool AcSaveContextHash(const char* context, BYTE out[32]) {
    AcRuntimeContext ctx;
    char title[64] = {};
    EnterCriticalSection(&g_lock);
    ctx = g_ctx;
    CopyClean(title, sizeof(title), g_licenseTitle);
    LeaveCriticalSection(&g_lock);
    std::string material = "korvayne-save-context-v1|title=";
    material += title;
    material += "|game="; material += ctx.gameId;
    material += "|env="; material += ctx.environment;
    material += "|identity="; material += ctx.identityProvider;
    material += "|player="; material += ctx.playerId;
    material += "|platform="; material += ctx.platformUserId;
    material += "|build="; material += ctx.gameBuild;
    material += "|ctx="; material += context ? context : "";
    return AcSha256((const BYTE*)material.data(), (DWORD)material.size(), out);
}

static void AcSaveXorStream(BYTE* data, uint32_t len, const BYTE key[32], const BYTE nonce[16]) {
    if (!data || len == 0) return;
    uint32_t off = 0;
    uint32_t counter = 0;
    while (off < len) {
        BYTE seed[32 + 16 + 4 + 16] = {};
        memcpy(seed, key, 32);
        memcpy(seed + 32, nonce, 16);
        AcPutU32(seed + 48, counter++);
        memcpy(seed + 52, "save-stream-v1", 14);
        BYTE block[32];
        if (!AcSha256(seed, sizeof(seed), block)) return;
        for (int i = 0; i < 32 && off < len; ++i, ++off) data[off] ^= block[i];
    }
}

static void AcSaveMacData(std::vector<BYTE>& mac, const BYTE* envelope, uint32_t payloadLen) {
    static const size_t TAG_OFF = 60;
    static const size_t PAYLOAD_OFF = 92;
    mac.clear();
    AcAppend(mac, envelope, TAG_OFF);
    AcAppend(mac, envelope + PAYLOAD_OFF, payloadLen);
}

static void AcSaveTamperEvent(const char* reason) {
    ac_severity sev;
    EnterCriticalSection(&g_lock);
    sev = g_saveGameTamperSeverity;
    LeaveCriticalSection(&g_lock);
    char msg[220];
    snprintf(msg, sizeof(msg), "savegame integrity check failed: %s", reason ? reason : "tampered or wrong context");
    ac_emit("SaveGame", sev, 0.95f, msg, 0);
}

int AC_ProtectSaveBuffer(const void* plain, unsigned plain_len, const char* context,
                         void* out_protected, unsigned out_cap, unsigned* out_len) {
    EnsureCoreInit();
    if (!AcRuntimeLicensed()) return AC_SAVE_UNLICENSED;
    bool enabled, obfuscate; unsigned maxBytes;
    EnterCriticalSection(&g_lock);
    enabled = g_saveGameEnabled; obfuscate = g_saveGameObfuscate; maxBytes = g_saveGameMaxBytes;
    LeaveCriticalSection(&g_lock);
    if (!enabled) return AC_SAVE_DISABLED;
    if ((plain_len > 0 && !plain) || !out_len) return AC_SAVE_BAD_ARGS;
    if (plain_len > maxBytes) return AC_SAVE_BAD_ARGS;

    static const BYTE MAGIC[4] = { 'K', 'S', 'V', '1' };
    static const uint16_t VERSION = 1;
    static const uint16_t FLAG_OBFUSCATED = 1;
    static const unsigned HEADER = 92;
    const unsigned need = HEADER + plain_len;
    *out_len = need;
    if (!out_protected || out_cap < need) return AC_SAVE_BUFFER_TOO_SMALL;

    BYTE key[32], ctxHash[32], nonce[16], tag[32];
    if (!AcSaveDeriveKey(key) || !AcSaveContextHash(context, ctxHash) || !AcRandomBytes(nonce, sizeof(nonce))) return AC_SAVE_CRYPTO_FAILED;

    BYTE* out = (BYTE*)out_protected;
    memset(out, 0, need);
    memcpy(out, MAGIC, 4);
    AcPutU16(out + 4, VERSION);
    AcPutU16(out + 6, obfuscate ? FLAG_OBFUSCATED : 0);
    AcPutU32(out + 8, plain_len);
    memcpy(out + 12, ctxHash, 32);
    memcpy(out + 44, nonce, 16);
    if (plain_len) memcpy(out + HEADER, plain, plain_len);
    if (obfuscate) AcSaveXorStream(out + HEADER, plain_len, key, nonce);

    std::vector<BYTE> mac;
    AcSaveMacData(mac, out, plain_len);
    if (!AcHmacSha256(key, sizeof(key), mac.data(), (DWORD)mac.size(), tag)) return AC_SAVE_CRYPTO_FAILED;
    memcpy(out + 60, tag, 32);
    return AC_SAVE_OK;
}

int AC_VerifySaveBuffer(const void* protected_buf, unsigned protected_len, const char* context,
                        void* out_plain, unsigned out_cap, unsigned* out_len) {
    EnsureCoreInit();
    if (!AcRuntimeLicensed()) return AC_SAVE_UNLICENSED;
    bool enabled; unsigned maxBytes;
    EnterCriticalSection(&g_lock);
    enabled = g_saveGameEnabled; maxBytes = g_saveGameMaxBytes;
    LeaveCriticalSection(&g_lock);
    if (!enabled) return AC_SAVE_DISABLED;
    if (!protected_buf || !out_len) return AC_SAVE_BAD_ARGS;

    static const BYTE MAGIC[4] = { 'K', 'S', 'V', '1' };
    static const uint16_t VERSION = 1;
    static const uint16_t FLAG_OBFUSCATED = 1;
    static const unsigned HEADER = 92;
    const BYTE* in = (const BYTE*)protected_buf;
    if (protected_len < HEADER || memcmp(in, MAGIC, 4) != 0 || AcGetU16(in + 4) != VERSION) {
        AcSaveTamperEvent("unsupported or missing protected-save envelope");
        return AC_SAVE_TAMPERED;
    }
    const uint16_t flags = AcGetU16(in + 6);
    if (flags & ~FLAG_OBFUSCATED) {
        AcSaveTamperEvent("unsupported protected-save flags");
        return AC_SAVE_TAMPERED;
    }
    const uint32_t payloadLen = AcGetU32(in + 8);
    *out_len = payloadLen;
    if (payloadLen > maxBytes || protected_len != HEADER + payloadLen) {
        AcSaveTamperEvent("protected-save length mismatch");
        return AC_SAVE_TAMPERED;
    }

    BYTE key[32], ctxHash[32], tag[32];
    if (!AcSaveDeriveKey(key) || !AcSaveContextHash(context, ctxHash)) return AC_SAVE_CRYPTO_FAILED;
    if (!AcConstEq32(in + 12, ctxHash)) {
        AcSaveTamperEvent("wrong save context");
        return AC_SAVE_TAMPERED;
    }

    std::vector<BYTE> mac;
    AcSaveMacData(mac, in, payloadLen);
    if (!AcHmacSha256(key, sizeof(key), mac.data(), (DWORD)mac.size(), tag)) return AC_SAVE_CRYPTO_FAILED;
    if (!AcConstEq32(in + 60, tag)) {
        AcSaveTamperEvent("payload or tag modified");
        return AC_SAVE_TAMPERED;
    }
    if (!out_plain || out_cap < payloadLen) return AC_SAVE_BUFFER_TOO_SMALL;
    if (payloadLen) memcpy(out_plain, in + HEADER, payloadLen);
    if (flags & FLAG_OBFUSCATED) AcSaveXorStream((BYTE*)out_plain, payloadLen, key, in + 44);
    return AC_SAVE_OK;
}

int AC_ProtectSaveFile(const char* path, const void* plain, unsigned plain_len, const char* context) {
    if (!path || !path[0]) return AC_SAVE_BAD_ARGS;
    unsigned need = 0;
    int rc = AC_ProtectSaveBuffer(plain, plain_len, context, nullptr, 0, &need);
    if (rc != AC_SAVE_BUFFER_TOO_SMALL || need == 0) return rc;
    std::vector<BYTE> out(need);
    rc = AC_ProtectSaveBuffer(plain, plain_len, context, out.data(), need, &need);
    if (rc != AC_SAVE_OK) return rc;
    FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") != 0 || !f) return AC_SAVE_IO_FAILED;
    size_t wr = fwrite(out.data(), 1, out.size(), f);
    bool ok = wr == out.size() && fflush(f) == 0;
    fclose(f);
    return ok ? AC_SAVE_OK : AC_SAVE_IO_FAILED;
}

int AC_VerifySaveFile(const char* path, const char* context, void* out_plain, unsigned out_cap, unsigned* out_len) {
    if (!path || !path[0] || !out_len) return AC_SAVE_BAD_ARGS;
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return AC_SAVE_IO_FAILED;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return AC_SAVE_IO_FAILED; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return AC_SAVE_IO_FAILED; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return AC_SAVE_IO_FAILED; }
    std::vector<BYTE> buf((size_t)sz);
    size_t rd = sz > 0 ? fread(buf.data(), 1, buf.size(), f) : 0;
    fclose(f);
    if (rd != buf.size()) return AC_SAVE_IO_FAILED;
    return AC_VerifySaveBuffer(buf.data(), (unsigned)buf.size(), context, out_plain, out_cap, out_len);
}

const char* AC_SaveResultName(int rc) {
    switch (rc) {
        case AC_SAVE_OK: return "ok";
        case AC_SAVE_BAD_ARGS: return "bad_args";
        case AC_SAVE_BUFFER_TOO_SMALL: return "buffer_too_small";
        case AC_SAVE_CRYPTO_FAILED: return "crypto_failed";
        case AC_SAVE_TAMPERED: return "tampered";
        case AC_SAVE_IO_FAILED: return "io_failed";
        case AC_SAVE_UNLICENSED: return "unlicensed";
        case AC_SAVE_DISABLED: return "disabled";
        default: return "unknown";
    }
}

static bool AcImportPubKeyMod(const unsigned char* mod, DWORD cbMod, BCRYPT_KEY_HANDLE* phKey) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0) != 0) return false;
    const DWORD cbExp = sizeof(AC_PUB_E);
    DWORD cb = sizeof(BCRYPT_RSAKEY_BLOB) + cbExp + cbMod;
    std::vector<BYTE> blob(cb);
    BCRYPT_RSAKEY_BLOB* h = (BCRYPT_RSAKEY_BLOB*)blob.data();
    h->Magic = BCRYPT_RSAPUBLIC_MAGIC; h->BitLength = cbMod * 8;
    h->cbPublicExp = cbExp; h->cbModulus = cbMod; h->cbPrime1 = 0; h->cbPrime2 = 0;
    memcpy(blob.data() + sizeof(BCRYPT_RSAKEY_BLOB), AC_PUB_E, cbExp);
    memcpy(blob.data() + sizeof(BCRYPT_RSAKEY_BLOB) + cbExp, mod, cbMod);
    NTSTATUS st = BCryptImportKeyPair(hAlg, nullptr, BCRYPT_RSAPUBLIC_BLOB, phKey, blob.data(), cb, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return st == 0;
}
static void AcParsePayload(const char* p, size_t n, AcLicense& L) {
    std::string s(p, n); size_t i = 0;
    while (i <= s.size()) {
        size_t semi = s.find(';', i);
        std::string kv = s.substr(i, semi == std::string::npos ? std::string::npos : semi - i);
        size_t eq = kv.find('=');
        if (eq != std::string::npos) {
            std::string k = kv.substr(0, eq), v = kv.substr(eq + 1);
            if      (k == "title") { strncpy(L.title, v.c_str(), sizeof(L.title) - 1); }
            else if (k == "cust")  { strncpy(L.customer, v.c_str(), sizeof(L.customer) - 1); }
            else if (k == "tier")  { L.tier = atoi(v.c_str()); }
            else if (k == "bk")    { strncpy(L.buildKey, v.c_str(), sizeof(L.buildKey) - 1); }
            else if (k == "feat")  { strncpy(L.features, v.c_str(), sizeof(L.features) - 1); }
            else if (k == "exp")   { L.exp = _strtoi64(v.c_str(), nullptr, 10); }
        }
        if (semi == std::string::npos) break;
        i = semi + 1;
    }
}
// Verify a token fully offline. Returns true only if the signature is valid AND the
// license is unexpired; L carries the parsed verdict either way (for the log reason).
// Verify a signed envelope  base64(payload) "." base64(sig)  against the EMBEDDED public key
// (RSA-2048 PKCS#1 v1.5 / SHA-256). On success returns true and hands back the verified payload
// bytes. Shared by the license gate AND the signed-signatures update channel â€” one audited path.
static bool AcVerifySignedKey(const char* token, const unsigned char* mod, DWORD cbMod, std::vector<BYTE>& payloadOut) {
    if (!token || !*token) return false;
    const char* dot = strchr(token, '.');
    if (!dot || dot == token || !dot[1]) return false;
    std::vector<BYTE> payload, sig;
    if (!AcB64Decode(token, (size_t)(dot - token), payload)) return false;
    if (!AcB64Decode(dot + 1, strlen(dot + 1), sig)) return false;
    BYTE hash[32];
    if (!AcSha256(payload.data(), (DWORD)payload.size(), hash)) return false;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!AcImportPubKeyMod(mod, cbMod, &hKey)) return false;
    BCRYPT_PKCS1_PADDING_INFO pad; pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    NTSTATUS st = BCryptVerifySignature(hKey, &pad, hash, 32, sig.data(), (DWORD)sig.size(), BCRYPT_PAD_PKCS1);
    BCryptDestroyKey(hKey);
    if (st != 0) return false;                 // forged / corrupted signature
    payloadOut.swap(payload);
    return true;
}
// License envelope -> embedded license key.
static bool AcVerifySigned(const char* token, std::vector<BYTE>& payloadOut) {
    return AcVerifySignedKey(token, AC_PUB_N, sizeof(AC_PUB_N), payloadOut);
}
static bool AcVerifyLicense(const char* token, AcLicense& L) {
    memset(&L, 0, sizeof(L));
    std::vector<BYTE> payload;
    if (!AcVerifySigned(token, payload)) return false;
    L.sigOk = true;
    AcParsePayload((const char*)payload.data(), payload.size(), L);
    long long now = (long long)time(nullptr);
    // Fail-closed on expiry: a missing/zero/past exp is INVALID. Requiring exp>0 means a token
    // can never be perpetual-by-omission â€” every license has a bounded lifetime, so an issuer
    // mistake (or a forged-but-impossible exp-less token) cannot outlive its term.
    L.expired = (L.exp <= 0) || (now >= L.exp);
    L.malformed = (L.tier <= 0) || !L.buildKey[0] || !L.title[0] || !L.customer[0];
    L.valid = L.sigOk && !L.expired && !L.malformed;
    return L.valid;
}
// Fallback license source: read "anticheat.lic" next to the host exe (one token, trimmed).
static bool AcLoadLicenseFile(char* out, size_t cap) {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    for (int i = (int)n - 1; i >= 0; i--) if (path[i] == '\\' || path[i] == '/') { path[i + 1] = 0; break; }
    strcat_s(path, MAX_PATH, "anticheat.lic");
    FILE* f = nullptr; if (fopen_s(&f, path, "rb") != 0 || !f) return false;
    size_t rd = fread(out, 1, cap - 1, f); fclose(f);
    out[rd] = 0;
    while (rd > 0) { char c = out[rd - 1]; if (c == '\n' || c == '\r' || c == ' ' || c == '\t') out[--rd] = 0; else break; }
    return rd > 0;
}
// Run the license gate once, at first arm. Emits the verdict through the sink (so it lands
// in the customer's log/telemetry) and returns whether sensors are allowed to arm.
static bool AcLicenseGate(const ac_config* cfg) {
    (void)cfg;   // open-source build: no license gate; the SDK always arms at full capability.
    return true;
}

// ---------------------------------------------------------------------------
//  Signed detection-signature update channel (Step 3)
// ----------------------------------------------------------------------------
//  A SIGNED deny-list of known-cheat module SHA-256 hashes, loaded from
//  "anticheat.sigs" next to the host exe (same RSA key as licenses, same verify
//  path). Security properties:
//   * It can only ADD detections â€” a matched hash raises HIGH regardless of the
//     module's Authenticode signature. It never disables a built-in sensor.
//   * Therefore a MISSING, OLD, or FORGED file cannot reduce protection below the
//     built-in heuristic baseline: an unverifiable file is ignored, not trusted.
//   * Tamper-proof: an attacker can't drop a file that says "trust cheat.dll" nor
//     strip entries â€” any edit breaks the signature and the whole file is dropped.
//  Payload (newline-delimited):
//     v=1;epoch=<unix>
//     sha256=<64hex>;label=<name>
//     ...
//  Distribution (the "update channel") is just shipping/fetching a newer signed
//  file; an optional backend pull reuses the WinHTTP client (wired in Step 4).
// ---------------------------------------------------------------------------
// (SigEntry / g_sigDb / AcHexToBytes / AcSha256File / AcMatchSig are defined above the Module
//  sensor so that sensor can consult the deny-list. AcParseSigs + AcLoadSignatures live here
//  because they depend on AcVerifySigned, defined just above.)
static void AcParseSigs(const char* p, size_t n) {
    std::string s(p, n); size_t i = 0;
    while (i <= s.size()) {
        size_t nl = s.find('\n', i);
        std::string line = s.substr(i, nl == std::string::npos ? std::string::npos : nl - i);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.rfind("v=", 0) == 0) {
            size_t e = line.find("epoch=");
            if (e != std::string::npos) g_sigEpoch = _strtoi64(line.c_str() + e + 6, nullptr, 10);
        } else if (line.rfind("sha256=", 0) == 0 && line.size() >= 7 + 64) {
            SigEntry se; memset(&se, 0, sizeof(se));
            if (AcHexToBytes(line.c_str() + 7, se.hash, 32)) {
                size_t lp = line.find("label=");
                if (lp != std::string::npos) { strncpy(se.label, line.c_str() + lp + 6, sizeof(se.label) - 1); se.label[sizeof(se.label) - 1] = 0; }
                g_sigDb.push_back(se);
            }
        }
        if (nl == std::string::npos) break;
        i = nl + 1;
    }
}
static void AcLoadSignatures() {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return;
    for (int i = (int)n - 1; i >= 0; i--) if (path[i] == '\\' || path[i] == '/') { path[i + 1] = 0; break; }
    strcat_s(path, MAX_PATH, "anticheat.sigs");
    FILE* f = nullptr; if (fopen_s(&f, path, "rb") != 0 || !f) return;   // absent -> built-in detection only (no weakening)
    std::string tok; { char buf[8192]; size_t rd; while ((rd = fread(buf, 1, sizeof(buf), f)) > 0) tok.append(buf, rd); } fclose(f);
    while (!tok.empty()) { char c = tok.back(); if (c == '\n' || c == '\r' || c == ' ' || c == '\t') tok.pop_back(); else break; }
    std::vector<BYTE> payload;
    if (!AcVerifySigned(tok.c_str(), payload)) {
        ac_emit("SigUpdate", AC_SEV_MED, 0.0f, "anticheat.sigs present but signature INVALID - ignored (built-in detection unaffected)", 0);
        return;
    }
    AcParseSigs((const char*)payload.data(), payload.size());
    char m[160]; snprintf(m, sizeof(m), "loaded %zu signed cheat signatures (epoch %lld)", g_sigDb.size(), g_sigEpoch);
    ac_emit("SigUpdate", AC_SEV_INFO, 1.0f, m, 0);
}

// ---------------------------------------------------------------------------
//  Lifecycle
// ---------------------------------------------------------------------------
static DWORD WINAPI ScanThread(LPVOID) {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (nt) {
        g_NtQSI = (NtQSI_t)(void*)GetProcAddress(nt, "NtQuerySystemInformation");
        g_NtQIP = (NtQIP_t)(void*)GetProcAddress(nt, "NtQueryInformationProcess");
    }
    g_acStartTick = GetTickCount64();
    ModuleSensor_Refresh(true);   // capture the legitimate startup module baseline
    CodeIntegrity_Init();         // baseline ntdll/kernelbase prologues (pre-existing hooks ignored)
    AcLoadSignatures();           // signed cheat-hash deny-list (Step 3); absent/forged -> built-in only
    LONG64 lastWatch = g_watchBeat; int wmiss = 0;
    while (InterlockedCompareExchange(&g_running, 1, 1)) {
        if (!AcRuntimeLicensed()) {
            ac_emit("SelfProtect", AC_SEV_CRIT, 1.0f, "SDK runtime license state lost - sensors stopping", 0);
            InterlockedExchange(&g_running, 0);
            break;
        }
        InterlockedIncrement64((volatile LONG64*)&g_scanBeat);
#ifdef AC_STANDALONE_TEST
        if (InterlockedExchange(&g_testStall, 0)) Sleep(4000);   // self-test only: simulate a suspend
#endif
        HandleSensor_Check();
        MemScanSensor_Check();
        ModuleSensor_Refresh(false);
        AntiDbgSensor_Check();
        CodeIntegrity_Check();
        if (g_watchBeat == lastWatch) {                          // mutual: is the watchdog alive?
            if (++wmiss >= 3) { ac_emit("SelfProtect", AC_SEV_HIGH, 0.90f, "AC watchdog thread stalled/suspended (anti-cheat tamper)", 0); wmiss = 0; }
        } else { wmiss = 0; lastWatch = g_watchBeat; }
        // Fast ValueGuard sub-loop: poll + enforce the cooperative value guards every
        // ~50ms (not just once per heavy-sensor cycle) so a restore lands promptly. The
        // heavy Handle/MemScan enumeration stays at scan_interval; this sums to one
        // scan_interval, so the watchdog beat cadence is unchanged.
        {
            const int step = 50; int e = 0, iv = (int)g_cfg.scan_interval_ms;
            ValueGuard_Check();
            while (InterlockedCompareExchange(&g_running, 1, 1) && e < iv) { Sleep(step); ValueGuard_Check(); e += step; }
        }
    }
    return 0;
}

// Defense-in-depth (per-build keying): fold the per-license build key into the ValueGuard
// session key, re-basing already-registered guards so nothing desyncs. This binds the value
// obfuscation to per-customer key material (on top of any compile-time ACSDK_BUILD_SALT), so a
// cheat reverse-engineered against one licensed build's shadow scheme does not carry to another.
// Called once, under g_lock, BEFORE the scan threads start â€” so there is no concurrent
// ValueGuard_Check and the re-base is race-free. Re-basing uses shadow algebra only (never reads
// the guarded memory), so a value tampered between registration and AC_Init is still caught.
static void AcBindSessionKey() {
    if (!g_buildKey[0]) return;                       // only when a real license produced a key
    uint32_t mix = fnv1a(g_buildKey);
    if (mix == 0) mix = 0x9E3779B9u;
    EnterCriticalSection(&g_lock);
    uint32_t oldKey = g_sessionKey, newKey = oldKey ^ mix;
    if (newKey == 0) newKey = 0xA5A5A5A5u;
    // old shadow encodes value as (value ^ oldKey); value ^ newKey == shadow ^ oldKey ^ newKey.
    for (auto& g : g_guards) g.shadow ^= (oldKey ^ newKey);
    g_sessionKey = newKey;
    LeaveCriticalSection(&g_lock);
}

// Online activation / revocation (Step 5). Returns true to ALLOW arming. FAIL-OPEN: an unreachable
// backend or an "unknown"/"active" status keeps the (already-valid) offline verdict, so air-gapped
// and LAN installs are unaffected. Only a definitive "revoked"/"expired" from the backend denies â€”
// the central kill-switch that offline verification can't provide. A deny is only honored when the
// reply carries a valid, build-bound VERDICT SIGNATURE (verified against AC_VERDICT_N), so a forged
// "revoked" cannot grief a paying customer; an unsigned/forged/mismatched reply fails open. Reuses
// HttpPostBytes, which forces TLS and attaches X-AC-Build only to the Korvayne activation request.
// Extract a JSON string value  "key":"value"  (our verdict fields carry no escapes). out is emptied
// first; returns false (out stays "") if the key is absent.
static bool AcJsonStr(const char* body, const char* key, char* out, size_t cap) {
    if (cap) out[0] = 0; else return false;
    char pat[40]; int pn = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (pn <= 0 || (size_t)pn >= sizeof(pat)) return false;
    const char* p = strstr(body, pat);
    if (!p) return false;
    p = strchr(p + pn, ':'); if (!p) return false;
    p++; while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return false;
    p++;
    const char* q = strchr(p, '"'); if (!q) return false;
    size_t n = (size_t)(q - p); if (n >= cap) n = cap - 1;
    memcpy(out, p, n); out[n] = 0;
    return true;
}
// Extract a ';'-delimited  key=value  field from a verdict payload (bounded copy).
static bool AcKvField(const char* payload, size_t len, const char* key, char* out, size_t cap) {
    if (cap) out[0] = 0;
    std::string s(payload, len), k = std::string(key) + "=";
    size_t i = 0;
    while (i < s.size()) {
        size_t semi = s.find(';', i);
        std::string tok = s.substr(i, semi == std::string::npos ? std::string::npos : semi - i);
        if (tok.compare(0, k.size(), k) == 0) {
            std::string v = tok.substr(k.size());
            if (cap) { strncpy(out, v.c_str(), cap - 1); out[cap - 1] = 0; }
            return true;
        }
        if (semi == std::string::npos) break;
        i = semi + 1;
    }
    return false;
}
static bool AcActivateOnline() {
    if (!g_activate || !g_buildKey[0]) return true;            // disabled -> offline verdict stands
    wchar_t whost[64]; MultiByteToWideChar(CP_UTF8, 0, g_backendHost, -1, whost, 64); whost[63] = 0;
    std::string resp;
    if (!HttpPostBytes(whost, (INTERNET_PORT)g_backendPort, L"/activate", nullptr, 0, resp)) {
        ac_emit("License", AC_SEV_INFO, 1.0f, "activation: backend unreachable - offline license stands", 0);
        return true;                                           // fail-open (preserve offline use)
    }
    // The authoritative verdict is the SIGNED token; the plaintext status is advisory only and is
    // NEVER trusted for a deny. No signed token / bad signature / wrong build -> fail-open.
    char vtoken[1024];
    if (!AcJsonStr(resp.c_str(), "vtoken", vtoken, sizeof(vtoken)) || !vtoken[0]) {
        ac_emit("License", AC_SEV_INFO, 1.0f, "activation: reply not signed - offline license stands", 0);
        return true;
    }
    std::vector<BYTE> payload;
    if (!AcVerifySignedKey(vtoken, AC_VERDICT_N, sizeof(AC_VERDICT_N), payload)) {
        ac_emit("License", AC_SEV_INFO, 1.0f, "activation: verdict signature invalid - offline license stands", 0);
        return true;                                           // untrusted reply -> fail-open
    }
    char vbk[80] = "", vstatus[24] = "";
    AcKvField((const char*)payload.data(), payload.size(), "bk", vbk, sizeof(vbk));
    AcKvField((const char*)payload.data(), payload.size(), "status", vstatus, sizeof(vstatus));
    if (strcmp(vbk, g_buildKey) != 0) {                        // signed, but for a different build
        ac_emit("License", AC_SEV_INFO, 1.0f, "activation: verdict build mismatch - offline license stands", 0);
        return true;
    }
    if (!strcmp(vstatus, "revoked") || !strcmp(vstatus, "expired")) {
        char m[176]; snprintf(m, sizeof(m), "activation DENIED: signed backend verdict reports license %s - sensors NOT armed", vstatus);
        ac_emit("License", AC_SEV_CRIT, 1.0f, m, 0);
        return false;                                          // tamper-evident central revocation
    }
    char m[128]; snprintf(m, sizeof(m), "activation: %s (signed online check passed)", vstatus[0] ? vstatus : "active");
    ac_emit("License", AC_SEV_INFO, 1.0f, m, 0);
    return true;
}

// Self-integrity (Step 5). Verify the SDK's OWN module is validly Authenticode-signed â€” a byte
// patch of our signed binary breaks the signature and fails this. It is a no-op for the static-lib
// build (our code lives in the customer's exe, which we don't sign) and for an as-yet-unsigned dev
// build. Enforcement is gated by ACSDK_REQUIRE_SELFSIGNED so it only bites once the DLL is signed
// with your cert. NOTE: this accepts ANY valid Authenticode signer; pin your publisher/thumbprint
// here once the cert exists to also reject a re-signed (attacker-cert) copy.
enum AcSelfState { AC_SELF_OK, AC_SELF_UNSIGNED, AC_SELF_NA };
static AcSelfState AcSelfIntegrity() {
    HMODULE hSelf = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)&AcSelfIntegrity, &hSelf) || !hSelf) return AC_SELF_NA;
    if (hSelf == GetModuleHandleW(nullptr)) return AC_SELF_NA;   // static-linked into host exe -> N/A
    wchar_t path[MAX_PATH]; DWORD n = GetModuleFileNameW(hSelf, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return AC_SELF_NA;
    SigVerdict v = ClassifyFileSig(path);
    return v == SIG_TRUSTED ? AC_SELF_OK : (v == SIG_UNTRUSTED ? AC_SELF_UNSIGNED : AC_SELF_NA);
}

int AC_Init(const ac_config* cfg) {
    if (!cfg || !cfg->cb) return -1;
    EnsureCoreInit();   // lock + session key are ready (also covers pre-AC_Init guard calls)
    EnterCriticalSection(&g_lock);
    g_cfg = *cfg;
    if (!g_cfg.scan_interval_ms) g_cfg.scan_interval_ms = 750;
    g_enforceRestore = (g_cfg.flags & AC_FLAG_VALUEGUARD_RESTORE) != 0;
    g_terminateOnTamper = (g_cfg.flags & AC_FLAG_TERMINATE_ON_TAMPER) != 0;
    g_ejectOnReader = (g_cfg.flags & AC_FLAG_EJECT_ON_READER) != 0;
    // Re-cap on a REPEAT AC_Init: a second (idempotent) call re-derives these from cfg.flags and
    // returns at the g_started gate below, before the post-gate cap runs â€” so apply the license
    // cap here too once licensed, or an integrator could lift the entitlement by calling twice.
    LeaveCriticalSection(&g_lock);
    // (per-session ValueGuard key was derived eagerly in EnsureCoreInit so values
    //  registered before AC_Init use the same key and never desync.)
    // Exactly one caller starts the threads (idempotent per acsdk.h). A concurrent/second
    // AC_Init only adopts the new callback above; it must NOT spawn a second thread pair.
    if (InterlockedCompareExchange(&g_started, 1, 0) != 0) return 0;

    // License gate (Step 2): verify the signed license offline BEFORE arming. On an
    // unlicensed/expired/forged token in a gated (shipping) build, refuse to arm â€” the
    // product simply provides no protection â€” but never crash the paying host. Reset
    // g_started so a later AC_Init carrying a valid license can still arm.
    if (!AcLicenseGate(cfg)) { InterlockedExchange(&g_started, 0); return -3; }

    // Online activation / revocation (opt-in; fail-open). A backend "revoked"/"expired" is the
    // one hard online deny; unreachable -> the offline verdict above stands.

    // Self-integrity: mechanism always runs; enforcement only when built signed-required.
    { AcSelfState si = AcSelfIntegrity();
#ifdef ACSDK_REQUIRE_SELFSIGNED
      if (si == AC_SELF_UNSIGNED) {
          ac_emit("SelfProtect", AC_SEV_CRIT, 1.0f, "SDK module is not validly code-signed (tamper/patched?) - sensors NOT armed", 0);
          AcClearLicenseRuntime();
          InterlockedExchange(&g_started, 0); return -3;
      }
#else
      if (si == AC_SELF_UNSIGNED)
          ac_emit("SelfProtect", AC_SEV_INFO, 1.0f, "self-integrity: SDK module not code-signed (enforcement off; build -DACSDK_REQUIRE_SELFSIGNED after signing)", 0);
#endif
    }

    // Cap enforcement to what the license entitles. The integrator may REQUEST any flag, but a
    // feature the license doesn't grant is masked off â€” so tier/feat are real commercial controls,
    // not just an informational string. (A dev/ungated unlicensed build keeps its flags, so it
    // stays testable offline.)
    // Bind the value-obfuscation key to the session (race-free; pre-thread).
    AcBindSessionKey();
    { char e[220];
      snprintf(e, sizeof(e), "enforcement active: restore=%d eject=%d eject_on_reader=%d handle_response=%s",
               g_enforceRestore, g_terminateOnTamper, g_ejectOnReader, HandleResponseName(g_handleResponse));
      ac_emit("Anticheat", AC_SEV_INFO, 1.0f, e, 0); }
    { char p[320];
      snprintf(p, sizeof(p), "response policy: module=%s memory=%s hook=%s debugger=%s selfprotect=%s behavior=%s",
               ModuleResponseName(g_moduleResponse), SensorResponseName(g_memoryResponse),
               SensorResponseName(g_hookResponse), SensorResponseName(g_debuggerResponse),
               SensorResponseName(g_selfProtectResponse), SensorResponseName(g_behaviorResponse));
      ac_emit("License", AC_SEV_INFO, 1.0f, p, 0); }

    InterlockedExchange(&g_running, 1);
    g_thread      = CreateThread(nullptr, 0, ScanThread, nullptr, 0, nullptr);
    g_watchThread = CreateThread(nullptr, 0, WatchdogThread, nullptr, 0, nullptr);
    if (!g_thread || !g_watchThread) {
        InterlockedExchange(&g_running, 0);
        if (g_thread && WaitForSingleObject(g_thread, 3000) == WAIT_OBJECT_0) { CloseHandle(g_thread); g_thread = nullptr; }
        if (g_watchThread && WaitForSingleObject(g_watchThread, 3000) == WAIT_OBJECT_0) { CloseHandle(g_watchThread); g_watchThread = nullptr; }
        AcClearLicenseRuntime();
        InterlockedExchange(&g_started, 0);
        return -2;
    }
    return 0;
}
void AC_Tick(void) { EnsureCoreInit(); ValueGuard_Check(); }   // cheap per-frame value-guard poll (matches acsdk.h)
void AC_Shutdown(void) {
    InterlockedExchange(&g_running, 0);
    // Only close a handle once its thread has actually exited; closing a still-running thread
    // and freeing g_cfg out from under it is a use-after-free. On timeout, leak the handle and
    // keep the callback intact (a slow WinVerifyTrust/network request can exceed the wait).
    if (g_thread      && WaitForSingleObject(g_thread, 3000)      == WAIT_OBJECT_0) { CloseHandle(g_thread);      g_thread = nullptr; }
    if (g_watchThread && WaitForSingleObject(g_watchThread, 5000) == WAIT_OBJECT_0) { CloseHandle(g_watchThread); g_watchThread = nullptr; }
    if (!g_thread && !g_watchThread) InterlockedExchange(&g_started, 0);   // both joined -> a later AC_Init may restart
}
const char* AC_Version(void) { return "acsdk 0.1.4-runtime (Handle/MemScan/Module/AntiDbg/CodeIntegrity/SelfProtect + ValueGuard/Aim/SaveGame)"; }

// ---------------------------------------------------------------------------
//  Drop-in ACModule mode: auto-init on DLL load + built-in file/debug sink, so
//  Phase 1 of UE_Integration.md (just LoadLibrary the DLL) turns on protection
//  with no game-code changes. Detections go to anticheat.log + OutputDebugString.
//  Built only for the ACModule.dll (cl /DACSDK_BUILD_DLL /DACSDK_DLL_AUTOINIT).
// ---------------------------------------------------------------------------
#if defined(ACSDK_BUILD_DLL) && defined(ACSDK_DLL_AUTOINIT)
static int g_logToFile = 1;   // drop-in file log next to the exe; turn off with [Logging] enabled=0
static void BuiltinSink(const ac_detection* d, void*) {
    static const char* S[] = { "INFO", "LOW", "MED", "HIGH", "CRIT" };
    char line[800];
    snprintf(line, sizeof(line), "[ACModule][%s] %s conf=%.2f %s\n", S[d->severity], d->sensor, d->confidence, d->message);
    OutputDebugStringA(line);                 // always available to the studio's own debug capture
    QueueTelemetry(d);
    if (!g_logToFile) return;                 // file logging is opt-out (see [Logging] in anticheat.ini)
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (n && n < MAX_PATH) { for (int i = (int)n - 1; i >= 0; i--) if (path[i] == '\\' || path[i] == '/') { path[i + 1] = 0; break; } strcat_s(path, sizeof(path), "anticheat.log"); }
    else strcpy_s(path, sizeof(path), "anticheat.log");
    FILE* f = nullptr; if (fopen_s(&f, path, "a") == 0 && f) { fputs(line, f); fclose(f); }
}
static DWORD WINAPI BootstrapThread(LPVOID) {
    Sleep(50);   // let the loader lock release before doing real work

    // Drop-in policy is fully configurable WITHOUT a recompile: read anticheat.ini
    // next to the host exe (same place as anticheat.log). Missing file/keys -> the
    // built-in defaults below. (A customer who links the SDK instead drives AC_Init
    // with their own flags + callback, e.g. disconnect/kick instead of terminate.)
    char ini[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr, ini, MAX_PATH);
    if (n && n < MAX_PATH) { for (int i = (int)n - 1; i >= 0; i--) if (ini[i] == '\\' || ini[i] == '/') { ini[i + 1] = 0; break; } strcat_s(ini, sizeof(ini), "anticheat.ini"); }
    else strcpy_s(ini, sizeof(ini), "anticheat.ini");

    AcRuntimeContext iniCtx;
    AcTelemetryPolicy iniTel;
    EnterCriticalSection(&g_lock);
    iniCtx = g_ctx;
    iniTel = g_tel;
    LeaveCriticalSection(&g_lock);

    char tmp[512];
    GetPrivateProfileStringA("Identity", "game_id", "", tmp, sizeof(tmp), ini); if (tmp[0]) CopyClean(iniCtx.gameId, sizeof(iniCtx.gameId), tmp);
    GetPrivateProfileStringA("Identity", "environment", "", tmp, sizeof(tmp), ini); if (tmp[0]) CopyClean(iniCtx.environment, sizeof(iniCtx.environment), tmp);
    GetPrivateProfileStringA("Identity", "provider", "", tmp, sizeof(tmp), ini); if (tmp[0]) CopyClean(iniCtx.identityProvider, sizeof(iniCtx.identityProvider), tmp);
    iniCtx.requireVerifiedIdentity = GetPrivateProfileIntA("Identity", "require_verified_identity", 1, ini) != 0;

    GetPrivateProfileStringA("Telemetry", "min_severity", "low", tmp, sizeof(tmp), ini);
    iniTel.minSeverity = ParseSeverity(tmp, AC_SEV_LOW);
    iniTel.batchIntervalMs = GetPrivateProfileIntA("Telemetry", "batch_interval_ms", 5000, ini);
    iniTel.redactPaths = GetPrivateProfileIntA("TelemetryFields", "redact_paths",
        GetPrivateProfileIntA("Telemetry", "redact_paths", 1, ini), ini) != 0;
    GetPrivateProfileStringA("Telemetry", "auth_header", "Authorization", tmp, sizeof(tmp), ini); CopyClean(iniTel.authHeader, sizeof(iniTel.authHeader), tmp);
    char tokenSource[40];
    GetPrivateProfileStringA("Telemetry", "token_source", "config_fallback", tokenSource, sizeof(tokenSource), ini);
    if (_stricmp(tokenSource, "runtime_session_token")) {
        GetPrivateProfileStringA("Telemetry", "auth_token", "", tmp, sizeof(tmp), ini); CopyClean(iniTel.authToken, sizeof(iniTel.authToken), tmp);
    }
    iniTel.eventInjection      = GetPrivateProfileIntA("TelemetryEvents", "injection", 1, ini) != 0;
    iniTel.eventHooks          = GetPrivateProfileIntA("TelemetryEvents", "hook_detection", 1, ini) != 0;
    iniTel.eventHandles        = GetPrivateProfileIntA("TelemetryEvents", "handle_checks", 1, ini) != 0;
    iniTel.eventDebugger       = GetPrivateProfileIntA("TelemetryEvents", "debugger", 1, ini) != 0;
    iniTel.eventBoot           = GetPrivateProfileIntA("TelemetryEvents", "boot_state", 1, ini) != 0;
    iniTel.eventMemory         = GetPrivateProfileIntA("TelemetryEvents", "memory_integrity", 1, ini) != 0;
    iniTel.eventSdkIntegrity   = GetPrivateProfileIntA("TelemetryEvents", "sdk_integrity", 1, ini) != 0;
    iniTel.eventProtectedValue = GetPrivateProfileIntA("TelemetryEvents", "protected_value", 1, ini) != 0;
    iniTel.eventAccessCheck    = GetPrivateProfileIntA("TelemetryEvents", "access_check", 1, ini) != 0;
    iniTel.eventAimBehavior    = GetPrivateProfileIntA("TelemetryEvents", "aim_behavior", 1, ini) != 0;
    iniTel.eventSaveGame       = GetPrivateProfileIntA("TelemetryEvents", "savegame_integrity", 1, ini) != 0;
    iniTel.fieldPlayerId       = GetPrivateProfileIntA("TelemetryFields", "player_id", 1, ini) != 0;
    iniTel.fieldSessionId      = GetPrivateProfileIntA("TelemetryFields", "session_id", 1, ini) != 0;
    iniTel.fieldPlatformUserId = GetPrivateProfileIntA("TelemetryFields", "platform_user_id", 1, ini) != 0;
    iniTel.fieldGameBuild      = GetPrivateProfileIntA("TelemetryFields", "game_build", 1, ini) != 0;
    iniTel.fieldSdkVersion     = GetPrivateProfileIntA("TelemetryFields", "sdk_version", 1, ini) != 0;
    iniTel.fieldModuleHash     = GetPrivateProfileIntA("TelemetryFields", "module_sha256", 1, ini) != 0;
    iniTel.fieldModuleSigner   = GetPrivateProfileIntA("TelemetryFields", "module_signer", 1, ini) != 0;
    iniTel.fieldActionTaken    = GetPrivateProfileIntA("TelemetryFields", "action_taken", 1, ini) != 0;
    iniTel.fieldServerObservedIp = GetPrivateProfileIntA("TelemetryFields", "server_observed_ip", 1, ini) != 0;
    iniTel.fieldHardwareId     = GetPrivateProfileIntA("TelemetryFields", "hardware_id", 0, ini) != 0;
    iniTel.fieldProcessNames   = GetPrivateProfileIntA("TelemetryFields", "process_names", 0, ini) != 0;

    AcEndpoint telEp = g_telemetryEndpoint;
    bool telEnabled = GetPrivateProfileIntA("Telemetry", "enabled", 0, ini) != 0;
    GetPrivateProfileStringA("Telemetry", "endpoint", "", tmp, sizeof(tmp), ini);
    telEp.enabled = telEnabled && ParseEndpointUrl(tmp, telEp);
    telEp.timeoutMs = GetPrivateProfileIntA("Telemetry", "timeout_ms", 2500, ini);

    AcEndpoint accessEp = g_accessEndpoint;
    bool accessEnabled = GetPrivateProfileIntA("AccessCheck", "enabled", 0, ini) != 0;
    GetPrivateProfileStringA("AccessCheck", "endpoint", "", tmp, sizeof(tmp), ini);
    accessEp.enabled = accessEnabled && ParseEndpointUrl(tmp, accessEp);
    accessEp.timeoutMs = GetPrivateProfileIntA("AccessCheck", "timeout_ms", 2500, ini);

    char failMode[24], onBanned[32], onSessionBan[32], accessProvider[32], accessMode[32], appealUrl[256];
    GetPrivateProfileStringA("AccessCheck", "fail_mode", "allow", failMode, sizeof(failMode), ini);
    GetPrivateProfileStringA("AccessCheck", "on_banned", "block_start", onBanned, sizeof(onBanned), ini);
    GetPrivateProfileStringA("AccessCheck", "on_session_ban", "disconnect", onSessionBan, sizeof(onSessionBan), ini);
    GetPrivateProfileStringA("AccessCheck", "provider", "studio_backend", accessProvider, sizeof(accessProvider), ini);
    GetPrivateProfileStringA("AccessCheck", "mode", "startup_and_recheck", accessMode, sizeof(accessMode), ini);
    GetPrivateProfileStringA("AccessCheck", "appeal_url", "", appealUrl, sizeof(appealUrl), ini);
    int accessRecheckInterval = GetPrivateProfileIntA("AccessCheck", "recheck_interval_sec", 300, ini);
    if (accessRecheckInterval < 30) accessRecheckInterval = 30;
    if (accessRecheckInterval > 3600) accessRecheckInterval = 3600;

    char handleResponse[40];
    GetPrivateProfileStringA("Enforcement", "handle_response", "corroborated",
                             handleResponse, sizeof(handleResponse), ini);
    char moduleResponse[40], memoryResponse[40], hookResponse[40], debuggerResponse[40];
    char selfProtectResponse[40], behaviorResponse[40];
    GetPrivateProfileStringA("Enforcement", "module_response", "report",
                             moduleResponse, sizeof(moduleResponse), ini);
    GetPrivateProfileStringA("Enforcement", "memory_response", "report",
                             memoryResponse, sizeof(memoryResponse), ini);
    GetPrivateProfileStringA("Enforcement", "hook_response", "report",
                             hookResponse, sizeof(hookResponse), ini);
    GetPrivateProfileStringA("Enforcement", "debugger_response", "report",
                             debuggerResponse, sizeof(debuggerResponse), ini);
    GetPrivateProfileStringA("Enforcement", "selfprotect_response", "report",
                             selfProtectResponse, sizeof(selfProtectResponse), ini);
    GetPrivateProfileStringA("Enforcement", "behavior_response", "report",
                             behaviorResponse, sizeof(behaviorResponse), ini);

    bool vgEnabled = GetPrivateProfileIntA("ValueGuard", "enabled", 0, ini) != 0;
    char vgAction[32]; GetPrivateProfileStringA("ValueGuard", "default_action", "", vgAction, sizeof(vgAction), ini);
    char vgSeverity[32]; GetPrivateProfileStringA("ValueGuard", "report_min_severity", "medium", vgSeverity, sizeof(vgSeverity), ini);
    int vgMaxTracked = GetPrivateProfileIntA("ValueGuard", "max_tracked_values", 128, ini);
    if (vgMaxTracked < 1) vgMaxTracked = 1;
    if (vgMaxTracked > 4096) vgMaxTracked = 4096;

    bool saveEnabled = GetPrivateProfileIntA("SaveGameProtection", "enabled", 1, ini) != 0;
    bool saveObfuscate = GetPrivateProfileIntA("SaveGameProtection", "obfuscate_payload", 1, ini) != 0;
    char saveSeverity[32]; GetPrivateProfileStringA("SaveGameProtection", "tamper_severity", "high", saveSeverity, sizeof(saveSeverity), ini);
    int saveMaxBytes = GetPrivateProfileIntA("SaveGameProtection", "max_save_bytes", 1048576, ini);
    if (saveMaxBytes < 1024) saveMaxBytes = 1024;
    if (saveMaxBytes > 64 * 1024 * 1024) saveMaxBytes = 64 * 1024 * 1024;

    EnterCriticalSection(&g_lock);
    g_ctx = iniCtx;
    g_tel = iniTel;
    g_telemetryEndpoint = telEp;
    g_accessEndpoint = accessEp;
    g_handleResponse = ParseHandleResponse(handleResponse);
    g_moduleResponse = ParseModuleResponse(moduleResponse);
    g_memoryResponse = ParseSensorResponse(memoryResponse, AC_RESP_REPORT);
    g_hookResponse = ParseSensorResponse(hookResponse, AC_RESP_REPORT);
    g_debuggerResponse = ParseSensorResponse(debuggerResponse, AC_RESP_REPORT);
    g_selfProtectResponse = ParseSensorResponse(selfProtectResponse, AC_RESP_REPORT);
    g_behaviorResponse = ParseSensorResponse(behaviorResponse, AC_RESP_REPORT);
    g_valueGuardEnabled = vgEnabled;
    g_valueGuardTerminate = !_stricmp(vgAction, "terminate");
    g_valueGuardSeverity = ParseSeverity(vgSeverity, AC_SEV_MED);
    g_valueGuardMaxTracked = (unsigned)vgMaxTracked;
    g_saveGameEnabled = saveEnabled;
    g_saveGameObfuscate = saveObfuscate;
    g_saveGameTamperSeverity = ParseSeverity(saveSeverity, AC_SEV_HIGH);
    g_saveGameMaxBytes = (unsigned)saveMaxBytes;
    g_accessRecheckIntervalSec = accessRecheckInterval;
    CopyClean(g_accessFailMode, sizeof(g_accessFailMode), failMode);
    CopyClean(g_accessOnBanned, sizeof(g_accessOnBanned), onBanned);
    CopyClean(g_accessOnSessionBan, sizeof(g_accessOnSessionBan), onSessionBan);
    CopyClean(g_accessProvider, sizeof(g_accessProvider), accessProvider);
    CopyClean(g_accessMode, sizeof(g_accessMode), accessMode);
    CopyClean(g_appealUrl, sizeof(g_appealUrl), appealUrl);
    LeaveCriticalSection(&g_lock);

    ac_config c; ZeroMemory(&c, sizeof(c)); c.cb = BuiltinSink;
    c.scan_interval_ms = (unsigned)GetPrivateProfileIntA("Enforcement", "scan_interval_ms", 1000, ini);
    unsigned flags = 0;
    if (GetPrivateProfileIntA("Enforcement", "restore",         0, ini)) flags |= AC_FLAG_VALUEGUARD_RESTORE;  // default off; new integrations start report-only
    if (GetPrivateProfileIntA("Enforcement", "eject",           0, ini)) flags |= AC_FLAG_TERMINATE_ON_TAMPER; // default OFF: terminating the game is opt-in (a single FP must not kill a paying customer)
    if (GetPrivateProfileIntA("Enforcement", "eject_on_reader", 0, ini)) flags |= AC_FLAG_EJECT_ON_READER;     // default off (higher-FP)
    c.flags = flags;
    // File log next to the exe is on by default; [Logging] enabled=0 turns it off (OutputDebugString stays).
    g_logToFile = GetPrivateProfileIntA("Logging", "enabled", 1, ini) ? 1 : 0;
    // Drop-in license source: anticheat.lic next to the host exe (NULL -> AC_Init auto-loads it).
    int rc = AC_Init(&c);

    if (rc == 0 && accessEp.enabled && _stricmp(accessMode, "server_guidance_only")) {
        char reason[220];
        bool allowed = RunAccessCheck(reason, sizeof(reason));
        ac_detection ad; ad.sensor = "AccessCheck"; ad.severity = allowed ? AC_SEV_INFO : AC_SEV_CRIT;
        ad.confidence = 1.0f; ad.message = reason[0] ? reason : (allowed ? "access allowed" : "access denied");
        ad.detail = 0;
        BuiltinSink(&ad, nullptr);
        if (!allowed && (!_stricmp(g_accessOnBanned, "block_start") || !_stricmp(g_accessOnBanned, "terminate"))) {
            EjectHost("access denied by backend - terminating host process");
        }
    }
    if (rc == 0 && accessEp.enabled && !_stricmp(accessMode, "startup_and_recheck")) {
        HANDLE h = CreateThread(nullptr, 0, AccessRecheckThread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    }

    char boot[320]; ac_severity sev = AC_SEV_INFO;
    if (rc == 0) {
        bool effectiveRestore, effectiveEject, effectiveReader;
        AcHandleResponse effectiveHandle;
        EnterCriticalSection(&g_lock);
        effectiveRestore = g_enforceRestore;
        effectiveEject = g_terminateOnTamper;
        effectiveReader = g_ejectOnReader;
        effectiveHandle = g_handleResponse;
        LeaveCriticalSection(&g_lock);
        snprintf(boot, sizeof(boot), "self-protection active (restore=%d eject=%d eject_on_reader=%d handle_response=%s scan=%ums)",
                 effectiveRestore, effectiveEject, effectiveReader, HandleResponseName(effectiveHandle), c.scan_interval_ms);
    } else if (rc == -3) {
        // The License sensor already logged the precise reason; this is the operator-facing summary.
        snprintf(boot, sizeof(boot), "protection NOT active: no valid license (place anticheat.lic next to the game exe)");
        sev = AC_SEV_CRIT;
    } else {
        snprintf(boot, sizeof(boot), "protection NOT active: AC_Init failed (%d)", rc);
        sev = AC_SEV_CRIT;
    }
    ac_detection d; d.sensor = "ACModule"; d.severity = sev; d.confidence = 1.0f;
    d.message = boot; d.detail = 0;
    BuiltinSink(&d, nullptr);
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); EnsureCoreInit(); CreateThread(nullptr, 0, BootstrapThread, nullptr, 0, nullptr); }
    else if (reason == DLL_PROCESS_DETACH) { InterlockedExchange(&g_running, 0); }   // signal stop only; NEVER join threads under the loader lock
    return TRUE;
}
#endif

// ---------------------------------------------------------------------------
//  Standalone self-test host (cl /DAC_STANDALONE_TEST)
// ---------------------------------------------------------------------------
#ifdef AC_STANDALONE_TEST
static void OnDetection(const ac_detection* d, void*) {
    static const char* SEV[] = { "INFO", "LOW", "MED", "HIGH", "CRIT" };
    printf("[AC][%s] %-10s conf=%.2f  %s\n", SEV[d->severity], d->sensor, d->confidence, d->message);
    fflush(stdout);
}
int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);   // unbuffered so redirected output is live
    bool plant = false, stall = false, aim = false, tamper = false;
    int runSeconds = 30;
    unsigned reqFlags = AC_FLAG_VALUEGUARD_RESTORE;   // default: restore only (no eject)
    static char licbuf[4096]; const char* licTok = nullptr; const char* loadDll = nullptr; const char* policy = nullptr;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--plant")) plant = true;
        else if (!strcmp(argv[i], "--stall")) stall = true;
        else if (!strcmp(argv[i], "--aim")) aim = true;
        else if (!strcmp(argv[i], "--tamper")) tamper = true;
        else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) {
            runSeconds = atoi(argv[++i]);
            if (runSeconds < 1) runSeconds = 1;
            if (runSeconds > 120) runSeconds = 120;
        }
        else if (!strcmp(argv[i], "--policy") && i + 1 < argc) policy = argv[++i];
        else if (!strcmp(argv[i], "--flags") && i + 1 < argc) {
            reqFlags = 0; const char* f = argv[++i];
            if (strstr(f, "restore")) reqFlags |= AC_FLAG_VALUEGUARD_RESTORE;
            if (strstr(f, "eject"))   reqFlags |= AC_FLAG_TERMINATE_ON_TAMPER;
            if (strstr(f, "reader"))  reqFlags |= AC_FLAG_EJECT_ON_READER;
        }
        else if (!strcmp(argv[i], "--loaddll") && i + 1 < argc) loadDll = argv[++i];
        else if (!strcmp(argv[i], "--license") && i + 1 < argc) licTok = argv[++i];
        else if (!strcmp(argv[i], "--lic-file") && i + 1 < argc) {
            FILE* lf = nullptr;
            if (fopen_s(&lf, argv[++i], "rb") == 0 && lf) {
                size_t rd = fread(licbuf, 1, sizeof(licbuf) - 1, lf); fclose(lf);
                licbuf[rd] = 0;
                while (rd > 0) { char c = licbuf[rd - 1]; if (c == '\n' || c == '\r' || c == ' ' || c == '\t') licbuf[--rd] = 0; else break; }
                licTok = licbuf;
            } else printf("could not open lic-file %s\n", argv[i]);
        }
    }
    if (policy) {
        if (!_stricmp(policy, "report")) {
            g_handleResponse = AC_HANDLE_CORROBORATED;
            g_moduleResponse = AC_MODULE_REPORT;
            g_memoryResponse = AC_RESP_REPORT;
            g_hookResponse = AC_RESP_REPORT;
            g_debuggerResponse = AC_RESP_REPORT;
            g_selfProtectResponse = AC_RESP_REPORT;
            g_behaviorResponse = AC_RESP_REPORT;
            g_valueGuardTerminate = false;
        } else if (!_stricmp(policy, "strict")) {
            g_handleResponse = AC_HANDLE_TERMINATE_WRITE;
            g_moduleResponse = AC_MODULE_TERMINATE_UNSIGNED;
            g_memoryResponse = AC_RESP_TERMINATE;
            g_hookResponse = AC_RESP_TERMINATE;
            g_debuggerResponse = AC_RESP_TERMINATE;
            g_selfProtectResponse = AC_RESP_TERMINATE;
            g_behaviorResponse = AC_RESP_REPORT;
        } else {
            g_handleResponse = AC_HANDLE_CORROBORATED;
            g_moduleResponse = AC_MODULE_REPORT;
            g_memoryResponse = AC_RESP_CORROBORATED;
            g_hookResponse = AC_RESP_CORROBORATED;
            g_debuggerResponse = AC_RESP_REPORT;
            g_selfProtectResponse = AC_RESP_REPORT;
            g_behaviorResponse = AC_RESP_REPORT;
            g_valueGuardTerminate = false;
        }
    }
    printf("acsdk self-test host  pid=%lu  plant=%d stall=%d aim=%d policy=%s seconds=%d license=%s\n",
           GetCurrentProcessId(), plant, stall, aim, policy ? policy : "default", runSeconds, licTok ? "provided" : "none");
    static volatile uint32_t score = 1000;
    // 'early' is registered BEFORE AC_Init â€” it exercises the per-license session-key re-base
    // (AcBindSessionKey must re-key its shadow without desyncing -> no startup FP, real tamper
    // still caught). 'score' is registered after AC_Init (the normal path).
    static volatile uint32_t early = 4242;
    printf("guarded 'score' at %p = %u ; 'early' (pre-init) at %p = %u\n", (void*)&score, score, (void*)&early, early);
    AC_GuardU32("early", (volatile unsigned*)&early);   // BEFORE AC_Init
    ac_config c; ZeroMemory(&c, sizeof(c)); c.cb = OnDetection; c.scan_interval_ms = 750;
    c.license = licTok; c.flags = reqFlags;
    int rc = AC_Init(&c);
    if (rc == -3) { printf("AC_Init -> refused to arm (rc=-3, self-integrity). host stays alive; exiting test.\n"); return 3; }
    if (rc != 0) { printf("AC_Init failed (%d)\n", rc); return 1; }
    printf("AC_Init -> armed (rc=0)\n");
    AC_GuardU32("score", (volatile unsigned*)&score);   // AFTER AC_Init
    if (tamper) {
        Sleep(1500);
        printf("TAMPER: out-of-band writes -> early=9999, score=8888 (expect ValueGuard detect + restore)\n");
        early = 9999; score = 8888;                     // direct writes, bypassing AC_SetGuardedU32
        for (int k = 0; k < 12 && (early != 4242 || score != 1000); k++) Sleep(100);
        printf("TAMPER result: early=%u (want 4242), score=%u (want 1000) -> %s\n",
               early, score, (early == 4242 && score == 1000) ? "RESTORED OK" : "NOT restored");
    }
    if (loadDll) {
        Sleep(5000);   // past AC_MODULE_WARMUP_MS so it counts as an injected (post-warm-up) load
        HMODULE h = LoadLibraryA(loadDll);
        printf("LoadLibrary('%s') -> %p (expect Module KNOWN CHEAT if its hash is in anticheat.sigs)\n", loadDll, (void*)h);
        Sleep(2000);   // let the next ModuleSensor_Refresh see it
    }
    if (aim) {
        Sleep(400);
        printf("AC_ReportAim human-like (slow aim, normal reaction, LOS) -> expect NOTHING\n");
        AC_ReportAim(0.2f, 250.0f, 1, 1);
        printf("AC_ReportAim super-human aim snap onto a hit -> expect AimSnap\n");
        AC_ReportAim(50.0f, 250.0f, 1, 1);
        printf("AC_ReportAim 3x sub-60ms reaction -> expect Triggerbot at x3\n");
        AC_ReportAim(1.0f, 20.0f, 1, 1); AC_ReportAim(1.0f, 25.0f, 1, 1); AC_ReportAim(1.0f, 18.0f, 1, 1);
        printf("AC_ReportAim hit with NO line of sight -> expect Wallhack\n");
        AC_ReportAim(1.0f, 250.0f, 0, 1);
    }
    if (plant) {
        // (a) fake manual-mapped PE image: exec region with MZ+PE not backed by a
        //     module -> EXPECT MemScan HIGH.
        void* mm = VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mm) { memcpy(mm, GetModuleHandleW(nullptr), 0x400); printf("planted manual-map PE image at %p\n", mm); }
        // (b) JIT-like exec region WITHOUT a PE header -> EXPECT NO flag (FP avoidance).
        void* jit = VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (jit) { memset(jit, 0x90, 0x400); printf("planted JIT-like exec region (no PE) at %p\n", jit); }
        // (c) LoadLibrary an UNSIGNED DLL AFTER the warm-up window -> EXPECT Module MED
        //     cheat-shaped (injection/input imports + cheat strings) -> high risk score.
        Sleep(5000);   // past AC_MODULE_WARMUP_MS so it counts as a post-warmup (injected) load
        wchar_t mod[MAX_PATH]; GetModuleFileNameW(nullptr, mod, MAX_PATH);
        wchar_t* sl = wcsrchr(mod, L'\\');
        if (sl) { wcscpy(sl + 1, L"samplecheat.dll"); HMODULE h = LoadLibraryW(mod);
                  wprintf(L"LoadLibrary samplecheat.dll -> %p\n", (void*)h); }
        //     stub -> EXPECT CodeIntegrity HIGH (thunk -> unbacked memory). The
        //     stub forwards to the original, so the import still works.
        {
            uint8_t* b = (uint8_t*)GetModuleHandleW(nullptr);
            IMAGE_DOS_HEADER* d = (IMAGE_DOS_HEADER*)b;
            IMAGE_NT_HEADERS* n = (IMAGE_NT_HEADERS*)(b + d->e_lfanew);
            IMAGE_DATA_DIRECTORY& id = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (id.VirtualAddress) {
                IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(b + id.VirtualAddress);
                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(b + desc->FirstThunk);
                if (thunk->u1.Function) {
                    void* orig = (void*)thunk->u1.Function;
                    uint8_t* stub = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (stub) {
                        stub[0] = 0x48; stub[1] = 0xB8; *(void**)(stub + 2) = orig; stub[10] = 0xFF; stub[11] = 0xE0;
                        DWORD old; VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old);
                        thunk->u1.Function = (ULONGLONG)(uintptr_t)stub;
                        VirtualProtect(&thunk->u1.Function, sizeof(void*), old, &old);
                        printf("planted IAT hook: thunk -> private stub %p (forwards to %p)\n", (void*)stub, orig);
                    }
                }
            }
        }
    }
    if (stall) { Sleep(3000); InterlockedExchange(&g_testStall, 1); printf("triggered scan-thread stall (watchdog should fire)\n"); }
    for (int i = 0; i < runSeconds * 4; i++) Sleep(250);
    AC_Shutdown();
    printf("self-test host done.\n");
    return 0;
}
#endif

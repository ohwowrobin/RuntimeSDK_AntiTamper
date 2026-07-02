# Optional: code-signing Korvayne Runtime

Signing is **optional**. The DLL built by `build_opensource.bat` is fully functional unsigned. Sign it only if you
want a signed binary — e.g. to reduce SmartScreen friction or to pin your own publisher in the
self-integrity check. Any code-signing certificate works; the steps below use SSL.com OV + eSigner
cloud signing as one example.

Whatever cert you use, sign **with a timestamp** — the timestamp keeps the signature valid even after
the cert later expires.

## One-time setup (example: SSL.com OV + eSigner)
1. Obtain an OV code-signing certificate with cloud (eSigner) signing from a CA of your choice.
2. Complete the CA's business validation (SSL.com verifies via a D-U-N-S number; usually 1–5 business
   days). Take the OV path, not EV.
3. **eSigner setup — pick ONE method:**
   - **CKA (Cloud Key Adapter):** install SSL.com's CKA tool; it exposes your cloud key as a virtual
     certificate so the standard Windows `signtool` can use it. Simplest for manual signing.
   - **CodeSignTool:** SSL.com's Java CLI for cloud signing (no token; good for CI/scripts).
   Note your `credential_id`, username, and TOTP secret from the SSL.com dashboard.

## Sign (run for each DLL)
SSL.com RFC-3161 timestamp server: **`http://ts.ssl.com`** (use your CA's timestamp URL if different).

**Option A — signtool via CKA** (after CKA is installed):
```
signtool sign /fd SHA256 /tr http://ts.ssl.com /td SHA256 /a anticheat.dll
```

**Option B — CodeSignTool (cloud, scriptable):**
```
CodeSignTool.bat sign -username=<email> -password=<pw> -credential_id=<id> ^
  -totp_secret=<secret> -input_file_path=anticheat.dll -output_dir_path=signed
```
(CodeSignTool timestamps automatically.)

## Verify
```
signtool verify /pa /v anticheat.dll
```
Expect **"Successfully verified"**, a timestamp line, and the signer = your organisation. Note the
exact **Subject / Issued-to name** from this output if you want to use publisher pinning below.

## Optional: publisher pinning + self-integrity
If you signed the DLL, you can harden it further:
1. **Pin your publisher** in the SDK's self-integrity check (to the exact subject above), so a
   *re-signed* copy with someone else's cert is rejected too — not just an unsigned one.
2. **Rebuild** with `ACSDK_REQUIRE_SELFSIGNED` → the DLL verifies its own signature at startup and
   refuses to arm if tampered.
3. **Sign that build, re-verify**, and ship it.

## Signing quota note
Cloud-signing plans often cap signings per month (SSL.com Basic ≈ 20/month) — plenty for one shared
signed `anticheat.dll`. Only a concern if you ship many per-build binaries (unique `ACSDK_BUILD_SALT`
each).

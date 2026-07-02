@echo off
REM Open-source Korvayne Runtime DLL: no licensing, no baked activation host.
REM Keeps the drop-in auto-init shape + CFG/CET hardening + version resource.
REM Output: core\out\anticheat.dll (+ anticheat.lib). Copy into the SDK package sdk\bin\ + sdk\lib\.
cd /d "C:\Users\robin\Desktop\TestTarget\acsdk\core"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if not exist out mkdir out
rc /nologo /fo out\acsdk_version.res acsdk_version.rc >out\build_os.log 2>&1
echo RC_EXIT=%errorlevel%
cl /nologo /LD /MT /EHsc /O2 /std:c++17 /W3 /guard:cf ^
   /DACSDK_BUILD_DLL /DACSDK_DLL_AUTOINIT ^
   acsdk.cpp out\acsdk_version.res /Fo:out\ /Fe:out\anticheat.dll /link /GUARD:CF /CETCOMPAT >>out\build_os.log 2>&1
echo DLL_EXIT=%errorlevel%
cl /nologo /EHsc /O2 /std:c++17 /W3 /DAC_STANDALONE_TEST acsdk.cpp /Fo:out\test_ /Fe:out\acsdk_ostest.exe >>out\build_os.log 2>&1
echo TEST_EXIT=%errorlevel%
type out\build_os.log | findstr /i "error fatal" && echo HAD_ERRORS || echo NO_ERRORS

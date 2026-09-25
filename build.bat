@echo off
rem Build the injector (x64). Requires MSVC BuildTools + Windows 10 SDK.
setlocal
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" set VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
call "%VCVARS%" >nul 2>&1
if errorlevel 1 ( echo [!] vcvars64.bat not found & exit /b 1 )

cl /nologo /std:c++17 /EHsc /O2 /W3 /D_CRT_SECURE_NO_WARNINGS ^
	PerfectInjector.cpp ^
	/Fe:PerfectInjector.exe /Fo:obj\ /link psapi.lib user32.lib advapi32.lib

if errorlevel 1 ( echo [!] build failed & exit /b 1 )
echo [+] Built PerfectInjector.exe
endlocal

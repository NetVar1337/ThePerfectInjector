@echo off
setlocal
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" set VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
call "%VCVARS%" >nul 2>&1
if errorlevel 1 ( echo [!] vcvars64.bat not found & exit /b 1 )

cl /nologo /std:c++17 /EHsc /O2 /W3 /D_CRT_SECURE_NO_WARNINGS test_mapper.cpp /Fe:test_mapper.exe /Fo:obj\ /link psapi.lib user32.lib advapi32.lib
if errorlevel 1 ( echo [!] test_mapper build failed & exit /b 1 )

cl /nologo /std:c++17 /EHsc /O2 /W3 /D_CRT_SECURE_NO_WARNINGS test_stub.cpp /Fe:test_stub.exe /Fo:obj\ /link psapi.lib user32.lib advapi32.lib
if errorlevel 1 ( echo [!] test_stub build failed & exit /b 1 )

echo [+] Built test_mapper.exe and test_stub.exe
endlocal

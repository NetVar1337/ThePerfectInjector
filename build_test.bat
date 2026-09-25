@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cl /nologo /std:c++17 /EHsc /O2 /W3 /D_CRT_SECURE_NO_WARNINGS test_mapper.cpp /Fe:test_mapper.exe /Fo:obj\ /link psapi.lib user32.lib advapi32.lib

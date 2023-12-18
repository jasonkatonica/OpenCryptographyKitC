rem Windows 64 environment setup
set PF=C:\Program Files
set PFX=C:\Program Files (x86)
set VSB=%PFX%\Microsoft Visual Studio 9.0
set VCW=%VSB%\VC
set SDKW=%PF%\Microsoft SDKs\Windows\v6.0A
set VC=%VCW%\bin\amd64
set SPL=C:\Strawberry
rem set the path for all the components needed to build OpenSSL
set PATH=%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SPL%\c\bin;%SPL%\perl\site\bin;%SPL%\perl\bin;%PFX%\nasm\;%VC%;%VSB%\Common7\IDE;%SDKW%\bin
rem setup so Windows programs can find headers/libs
set LIB1=%VCW%\Lib\amd64
set LIB2=%SDKW%\lib\x64
set LIB=%LIB1%;%LIB2%
rem Headers
set INC1=%VCW%\include
set INC2=%SDKW%\Include
set INC3=%VCW%\atlmfc\include
set INCLUDE=%INC1%;%INC2%;%INC3%
rem Normal working directory
set WK=x:\ICC8.5\win64_x86\icc
mkdir tmp
cd ..\openssl-1.1.1m
nmake
cd ..\icc


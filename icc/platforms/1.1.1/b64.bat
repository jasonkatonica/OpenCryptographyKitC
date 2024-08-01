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
set OSSLVER=%1
if x%OSSLVER% == x set OSSLVER=openssl-1.1.1
cd ..\%OSSLVER%
perl Configure VC-WIN64A no-engine no-sctp no-idea no-rc5 no-whirlpool no-zlib enable-mdc2 enable-camellia enable-md2 no-seed 
set MAKE=
set MAKEFLAGS=
nmake /f makefile
mkdir tmp32dll
copy /Y crypto\*.obj tmp32dll\
copy /Y ms\*.obj tmp32dll\
copy /Y apps\*.obj tmp32dll\
copy /Y ssl\*.obj tmp32dll\
copy /Y crypto\ec\curve448\*.obj tmp32dll\
copy /Y crypto\ec\curve448\arch_32\*.obj tmp32dll\
copy /Y crypto\async\arch\*.obj tmp32dll\
FOR /D %%G in ( crypto/* ) DO copy /Y crypto\%%G\*.obj tmp32dll\
FOR /D %%G in ( ssl/* ) DO copy /Y ssl\%%G\*.obj tmp32dll\




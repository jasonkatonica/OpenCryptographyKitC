# Microsoft Developer Studio Project File - Name="icc" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) External Target" 0x0106

CFG=icc - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "icc.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "icc.mak" CFG="icc - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "icc - Win32 Release" (based on "Win32 (x86) External Target")
!MESSAGE "icc - Win32 Debug" (based on "Win32 (x86) External Target")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""

!IF  "$(CFG)" == "icc - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir ""
# PROP BASE Intermediate_Dir ""
# PROP BASE Cmd_Line "make OPSYS=WIN32"
# PROP BASE Rebuild_Opt "clean_all"
# PROP BASE Target_File "icctest.exe"
# PROP BASE Bsc_Name "icctest.bsc"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ""
# PROP Intermediate_Dir ""
# PROP Cmd_Line "make OPSYS=WIN32"
# PROP Rebuild_Opt "clean_all all"
# PROP Target_File "icctest.exe"
# PROP Bsc_Name "icctest.bsc"
# PROP Target_Dir ""

!ELSEIF  "$(CFG)" == "icc - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir ""
# PROP BASE Intermediate_Dir ""
# PROP BASE Cmd_Line "make OPSYS=WIN32 CONFIG=debug"
# PROP BASE Rebuild_Opt "clean_all"
# PROP BASE Target_File "icctest.exe"
# PROP BASE Bsc_Name "icctest.bsc"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ""
# PROP Intermediate_Dir ""
# PROP Cmd_Line "make OPSYS=WIN32 CONFIG=debug"
# PROP Rebuild_Opt "clean_all all"
# PROP Target_File "icctest.exe"
# PROP Bsc_Name "icctest.bsc"
# PROP Target_Dir ""

!ENDIF 

# Begin Target

# Name "icc - Win32 Release"
# Name "icc - Win32 Debug"

!IF  "$(CFG)" == "icc - Win32 Release"

!ELSEIF  "$(CFG)" == "icc - Win32 Debug"

!ENDIF 

# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\clic.c
# End Source File
# Begin Source File

SOURCE=.\fips.c
# End Source File
# Begin Source File

SOURCE=.\icc.c
# End Source File
# Begin Source File

SOURCE=.\icclib.c
# End Source File
# Begin Source File

SOURCE=.\icctest.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\clic.h
# End Source File
# Begin Source File

SOURCE=.\fips.h
# End Source File
# Begin Source File

SOURCE=..\package\iccsdk\icc.h
# End Source File
# Begin Source File

SOURCE=..\package\iccsdk\iccglobals.h
# End Source File
# Begin Source File

SOURCE=.\icchash.h
# End Source File
# Begin Source File

SOURCE=.\icclib.h
# End Source File
# Begin Source File

SOURCE=.\iccversion.h
# End Source File
# Begin Source File

SOURCE=.\platform.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project

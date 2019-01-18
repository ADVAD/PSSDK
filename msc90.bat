set MSSDK=g:\c\Microsoft SDKs\Windows\v6.0A
set MSVCDir=g:\c\vc90
set INCLUDE=.\;.\_include;%MSSDK%\include;%MSVCDir%\include;%MSVCDir%\atlmfc\include;g:\c\wtl80\include;g:\c\directx90\include
set LIB=.\;\g:\c\directx90\lib;%MSSDK%\lib;%MSVCDir%\lib;%MSVCDir%\atlmfc\lib

%MSVCDir%\bin\RC loaddrv1.rc

%MSVCDir%\bin\cl %1 /EHsc /DNDEBUG /DWIN32 /link /MACHINE:X86 kernel32.lib gdi32.lib user32.lib ws2_32.lib advapi32.lib loaddrv1.res %2


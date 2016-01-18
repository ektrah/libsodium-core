@echo off
REM Copy / Sign / Build NuGet Package

REM clear out any existing files
rm .\bin\*

REM copy files to ./bin
cp ..\libsodium-net\bin\Release\*.dll .\bin
cp ..\libsodium-net\bin\Release\*.config .\bin

REM sign the DLLs
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /a /fd SHA256 /t http://timestamp.certum.pl/ .\bin\*.dll

REM get the latest nuget - should fix the cert issue at some point
wget --no-check-certificate https://dist.nuget.org/win-x86-commandline/latest/nuget.exe 2> NUL

REM build and upload the nuget Package
nuget pack ..\libsodium-net.nuspec
nuget push *.nupkg

REM cleanup
rm *.nupkg
rm nuget.exe

pause

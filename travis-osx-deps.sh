#!/bin/bash
set -ev

MONO_VER=3.4.0

brew update
wget "http://download.mono-project.com/archive/${MONO_VER}/macos-10-x86/MonoFramework-MDK-${MONO_VER}.macos10.xamarin.x86.pkg"
sudo installer -pkg "MonoFramework-MDK-${MONO_VER}.macos10.xamarin.x86.pkg" -target /

mozroots --import --sync
mono --runtime=v4.0 ./.nuget/NuGet.exe restore ./libsodium-net.sln
echo "mono --runtime=v4.0  ./packages/NUnit.Runners.2.6.3/tools/nunit-console.exe \"\$@\"" > nunit-console.sh

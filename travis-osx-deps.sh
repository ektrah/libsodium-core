#!/bin/bash
set -ev

MONO_VER=3.4.0

brew update
brew install cmake

wget "http://download.mono-project.com/archive/${MONO_VER}/macos-10-x86/MonoFramework-MDK-${MONO_VER}.macos10.xamarin.x86.pkg"
sudo installer -pkg "MonoFramework-MDK-${MONO_VER}.macos10.xamarin.x86.pkg" -target /
echo "exec /Library/Frameworks/Mono.framework/Versions/${MONO_VER}/bin/mono --runtime=v4.0 --debug $MONO_OPTIONS /Library/Frameworks/Mono.framework/Versions/${MONO_VER}/lib/mono/2.0/nunit-console.exe \"$@\"" > nunit-console.sh

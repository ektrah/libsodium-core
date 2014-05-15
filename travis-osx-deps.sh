#!/bin/bash
set -ev

MONO_VER=3.4.0
NUNIT_VER=2.6.3

brew update
brew install cmake

wget "http://download.mono-project.com/archive/${MONO_VER}/macos-10-x86/MonoFramework-MDK-${MONO_VER}.macos10.xamarin.x86.pkg"
sudo installer -pkg "MonoFramework-MDK-${MONO_VER}.macos10.xamarin.x86.pkg" -target /

wget -O nunit.zip "http://launchpad.net/nunitv2/trunk/${NUNIT_VER}/+download/NUnit-${NUNIT_VER}.zip"
unzip nunit.zip
echo "mono --runtime=v4.0  ./NUnit-${NUNIT_VER}/bin/nunit-console.exe \"\$@\"" > nunit-console.sh

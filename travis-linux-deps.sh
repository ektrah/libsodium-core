#!/bin/bash
set -ev
lsb_release -a

sudo add-apt-repository -y "deb http://archive.ubuntu.com/ubuntu/ trusty main universe"
sudo apt-get update -qq -y
sudo apt-get install mono-complete -qq -y
mozroots --import --sync
mono --runtime=v4.0 ./.nuget/NuGet.exe restore ./libsodium-net.sln
echo 'mono --runtime=v4.0 ./packages/NUnit.Runners.2.6.3/tools/nunit-console.exe "$@"' > nunit-console.sh

mono --version

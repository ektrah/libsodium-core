#!/bin/bash
set -ev

sudo apt-get install mono-complete
mozroots --import --sync
mono --runtime=v4.0 ./.nuget/NuGet.exe restore ./libsodium-net.sln
echo 'mono --runtime=v4.0 ./packages/NUnit.Runners.2.6.3/tools/nunit-console.exe "$@"' > nunit-console.sh

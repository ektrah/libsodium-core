#!/bin/bash
set -ev

sudo apt-get install mono-devel mono-gmcs
mono ./.nuget/NuGet.exe restore ./libsodium-net.sln
echo 'mono ./packages/NUnit.Runners.2.6.3/tools/nunit-console.exe "$@"' > nunit-console.sh

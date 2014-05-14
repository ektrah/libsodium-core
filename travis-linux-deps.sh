#!/bin/bash
set -ev

sudo apt-get install mono-devel mono-gmcs nunit-console
echo "nunit-console \"$@\"" > nunit-console.sh

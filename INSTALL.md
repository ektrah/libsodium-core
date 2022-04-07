[![NuGet](https://img.shields.io/nuget/v/Sodium.Core)](https://www.nuget.org/packages/Sodium.Core)

**libsodium for .NET** can be installed as follows:

    dotnet add package Sodium.Core

The *Sodium.Core* package is intended to run on supported versions of .NET on the following platforms:

* Windows
    * `win-x64`
    * `win-x86`
* Linux
    * `linux-x64` (Most desktop distributions like CentOS, Debian, Fedora, Ubuntu, and derivatives)
    * `linux-musl-x64` (Lightweight distributions using musl like Alpine Linux)
    * `linux-arm` (Linux distributions running on ARM like Raspbian on Raspberry Pi Model 2+)
    * `linux-arm64` (Linux distributions running on 64-bit ARM like Ubuntu Server 64-bit on Raspberry Pi Model 3+)
* macOS
    * `osx-x64`
    * `osx-arm64`

Specifically, *Sodium.Core* 1.3.0 has been tested to run on the following platforms and .NET versions:

| OS       | Version    | Architectures | .NET |
|:---------|:---------- |:------------- |:-----|
| Windows  | 10.0.20348 | x64           | 6.0  |
| macOS    | 11.6       | x64           | 6.0  |
| Ubuntu   | 20.04      | x64           | 6.0  |

Other, similar platforms supported by .NET should work as well but have not been tested.

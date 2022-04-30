[![NuGet](https://img.shields.io/nuget/vpre/Sodium.Core)](https://www.nuget.org/packages/Sodium.Core/1.3.0)

**libsodium for .NET** can be installed as follows:

    dotnet add package Sodium.Core --version 1.3.0

The *Sodium.Core* package is intended to run on
[supported versions of .NET](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)
on the following platforms:

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

Specifically,
[Sodium.Core 1.3.0](https://www.nuget.org/packages/Sodium.Core/1.3.0)
has been tested to run on the following platforms and .NET versions:

| OS       | Version    | Architectures | .NET  |
|:---------|:---------- |:------------- |:------|
| Windows  | 10.0.20348 | x64           | 6.0.4 |
| macOS    | 11.6       | x64           | 6.0.4 |
| Ubuntu   | 20.04      | x64           | 6.0.4 |

Other, similar platforms supported by .NET should work as well but have not been tested.

Using libsodium on Windows requires the
[Microsoft Visual C++ Redistributable for Visual Studio 2015, 2017, 2019, and 2022](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads).
This dependency is included in the .NET SDK but might
not be present, for example, when deploying a self-contained application.

The implementation of AES-GCM in libsodium is hardware-accelerated and requires an
x64 processor with the AES-NI extension. The availability of this extension can
be determined at runtime using the static `IsAvailable` property of the
`Sodium.SecretAeadAes` class.

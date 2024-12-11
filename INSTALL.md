[![NuGet](https://img.shields.io/nuget/vpre/Sodium.Core)](https://www.nuget.org/packages/Sodium.Core/1.4.0-preview.1)

**libsodium for .NET** can be installed as follows:

    $ dotnet add package Sodium.Core --version 1.4.0-preview.1


## Supported Platforms

The *Sodium.Core* package is intended to run on all
[supported versions of .NET](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)
on the following platforms:

|                       | `-x64`   | `-x86`   | `-arm64` | `-arm`   |
|:----------------------|:--------:|:--------:|:--------:|:--------:|
| **`android-`**        |          |          |          |          |
| **`ios-`**            |          |          | &check;  |          |
| **`linux-`**          | &check;  |          | &check;  | &check;  |
| **`linux-musl-`**     | &check;  |          | &check;  | &check;  |
| **`maccatalyst-`**    | &check;  |          | &check;  |          |
| **`osx-`**            | &check;  |          | &check;  |          |
| **`tvos-`**           |          |          | &check;  |          |
| **`win-`**            | &check;  | &check;  | &check;  |          |


Please note:

1. For Windows, the
   [Microsoft Visual C++ Redistributable for Visual Studio 2015, 2017, 2019, and 2022](https://learn.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist)
   is required. This is part of the .NET SDK but might not be present on a
   clean Windows installation.

2. The AES-GCM implementation in libsodium is hardware-accelerated and may not be
   available on all architectures. Support can be determined at runtime using
   the static `IsAvailable` property of the `Sodium.SecretAeadAes` class.


## Tested Platforms

[Sodium.Core 1.4.0-preview.1](https://www.nuget.org/packages/Sodium.Core/1.4.0-preview.1)
has been tested to run on the following platforms and .NET versions:

| OS                   | Version  | Architecture  | .NET   |
|:-------------------- |:-------- |:------------- |:-------|
| Windows 11           | 23H2     | x64           | 8.0.11 |
| Windows Server 2022  | LTSC     | x64           | 8.0.11 |
| macOS                | 14.7     | arm64         | 8.0.11 |
| Alpine Linux         | 3.20     | x64           | 8.0.11 |
| Ubuntu               | 22.04    | x64           | 8.0.11 |

The other supported platforms should work as well, but have not been tested.


## Frequently Asked Questions

Below are some frequently asked questions:

**Q**: What causes a *System.DllNotFoundException: Unable to load shared
library 'libsodium' or one of its dependencies.* when using libsodium for .NET?  
**A**: This exception can occur if the operating system or architecture is not
supported, or if the Visual C++ Redistributable has not been installed on a
Windows system. Please refer to the [Supported Platforms](#supported-platforms)
section above.

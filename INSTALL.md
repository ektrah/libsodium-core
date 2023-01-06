[![NuGet](https://img.shields.io/nuget/vpre/Sodium.Core)](https://www.nuget.org/packages/Sodium.Core/1.3.2)

**libsodium for .NET** can be installed as follows:

    dotnet add package Sodium.Core --version 1.3.2

The *Sodium.Core* package is intended to run on
[supported versions of .NET](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)
on the following platforms:

|                       | `-x64`   | `-x86`   | `-arm64` | `-arm`   |
|:----------------------|:--------:|:--------:|:--------:|:--------:|
| **`win-`**            | &check;  | &check;  |          |          |
| **`linux-`**          | &check;  |          | &check;  | &check;  |
| **`linux-musl-`**     | &check;  |          | &check;  | &check;  |
| **`osx-`**            | &check;  |          | &check;  |          |
| **`ios-`**            |          |          |          |          |
| **`android-`**        |          |          |          |          |

Specifically,
[Sodium.Core 1.3.2](https://www.nuget.org/packages/Sodium.Core/1.3.2)
has been tested to run on the following platforms and .NET versions:

| OS                   | Version  | Architectures | .NET            |
|:-------------------- |:-------- |:------------- |:--------------- |
| Windows 10 Client    | 20H2     | x64           | 7.0.0 / 6.0.11  |
| Windows Server       | 2022     | x64           | 7.0.0 / 6.0.11  |
| macOS                | 11.7     | x64           | 7.0.0 / 6.0.11  |
| Ubuntu               | 22.04    | x64           | 7.0.0 / 6.0.11  |
| Alpine               | 3.16     | x64           | 7.0.0           |

Other, similar platforms supported by .NET should work as well but have not been tested.

Using libsodium on Windows requires the
[Microsoft Visual C++ Redistributable for Visual Studio 2015, 2017, 2019, and 2022](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads).
This dependency is included in the .NET SDK but might
not be present, for example, when deploying a self-contained application.

The implementation of AES-GCM in libsodium is hardware-accelerated and requires an
x64 processor with the AES-NI extension. The availability of this extension can
be determined at runtime using the static `IsAvailable` property of the
`Sodium.SecretAeadAes` class.

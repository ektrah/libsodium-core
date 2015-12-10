# libsodium-net [![Build Status](https://travis-ci.org/adamcaudill/libsodium-net.svg?branch=master)](https://travis-ci.org/adamcaudill/libsodium-net) [![NuGet Version](http://img.shields.io/nuget/v/libsodium-net.svg)](https://www.nuget.org/packages/libsodium-net/) [![License](http://img.shields.io/badge/license-MIT-green.svg)](https://github.com/adamcaudill/libsodium-net/blob/master/LICENSE)

libsodium-net, or better said, [libsodium](https://github.com/jedisct1/libsodium) for .NET, is a C# wrapper around libsodium. For those that don't know, libsodium is a portable implementation of [Daniel Bernstein's](http://cr.yp.to/djb.html) fantastic [NaCl](http://nacl.cr.yp.to/) library. If you aren't familiar with NaCl, I highly suggest that you look into libsodium and NaCl before using this library.

Want to support development? Consider donating via Bitcoin to `14jumFDmuVkLiAt4TgyKt17SWHtPRbkcLr` - all donations, no matter how small are appreciated.

## Why

NaCl is a great library in that its designed has made the right choices on what to implement and how - something most developers don't know how to do. So by using it (or a wrapper), many of those details are abstracted away where you don't need to worry about them. NaCl itself is less than portable C, only targeted for *nix systems; libsodium solves this by making it portable and making a few minor changes to better suite being distributed as a compiled binary.

Crypto is hard - much harder than your average developer understands. This effort was started to make these tools readily available to the .NET community in hopes they will be used to further the goals of defending personal privacy and security.

## Installation

**Windows**: For Windows, the `libsodium` library is included in the [release](https://github.com/adamcaudill/libsodium-net/releases) packages. Or just use the [NuGet version](https://www.nuget.org/packages/libsodium-net/) which has everything you need.

**OSX**: For OSX, `libsodium-net` can easily be built in Xamarin Studio, and `libsodium` can be installed easily via `brew`:

    brew install libsodium --universal

**Linux**: As with OSX, building with Xamarin Studio is simple, or there's always the option of using `xbuild`:

    xbuild libsodium-net.sln

For `libsodium`, many package managers provide older versions, so it's recommended to build the latest version from source. Thankfully, this is a fairly painless process. See the [travis-build-libsodium.sh](https://github.com/adamcaudill/libsodium-net/blob/master/travis-build-libsodium.sh) file or the `libsodium` [README](https://github.com/jedisct1/libsodium/blob/master/README.markdown) file for details.

**Other**: Support for other Mono supported platforms hasn't been determined. It may or may not work.

Note: For all platforms, it's critical that `libsodium` be compiled for the architecture that the process is running under. If they don't match, you can expect to see errors. If your process is x86/i386, you can't use a copy of `libsodium` compiled for x64.

## Documentation

[libsodium-net](http://bitbeans.gitbooks.io/libsodium-net/content/) documentation is available (an adapted copy of the [original](http://doc.libsodium.org/) written by Frank Denis ([@jedisct1](https://github.com/jedisct1))).

## Requirements & Versions

This library can be built in Visual Studio 2010, Xamarin Studio (MonoDevelop 3.x supported), and targets .NET 4.0; it is compiled against libsodium v1.0.6.

On OSX & Linux, your copy of `libsodium` must be compiled for the same architecture as your copy of Mono. If you are running a 32bit process, your copy of `libsodium` must be 32bit as well.

## Notes

Any method that takes a String, has an overload that accepts a byte array; Strings are assumed to be UTF8; if this is not the case, please convert it to bytes yourself and use the overloads that accept byte arrays.

`libsodium` requires the [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145).

## File Signing

Starting with version 0.4.0, all files are signed via a Certum.pl Code Signing certificate. The files are signed under the name `Open Source Developer, Adam Caudill` - this can be used to ensure that the files haven't been altered.

## License

NaCl has been released to the public domain to avoid copyright issues. libsodium is subject to the [ISC license](https://en.wikipedia.org/wiki/ISC_license), and this software is subject to the MIT license (see LICENSE).

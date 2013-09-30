# libsodium-net
libsodium-net, or better said, [libsodium](https://github.com/jedisct1/libsodium) for .NET, is a C# wrapper around libsodium. For those that don't know, libsodium is a portable implementation of [Daniel Bernstein's](http://cr.yp.to/djb.html) fantastic [NaCl](http://nacl.cr.yp.to/) library. If you aren't familiar with NaCl, you should probably do some reading before using this library.

## Why

NaCl is a great library in that its designed has made the right choices on what to implement and how - something most developers don't know how to do. So by using it (or a wrapper), many of those details are abstracted away where you don't need to worry about them. NaCl itself is less than portable C, only targeted for *nix systems; libsodium solves this by making it portable and making a few minor changes to better suite being distributed as a compiled binary.

## No really, why?

Crypto is hard - much harder than your average developer understands. There is much going on in the world today, privacy is at risk like never before - many complain, few act. To avoid falling into the complainers group, I've started this effort to make these tools readily available to the .NET community in hopes they will be used to further the goals of defending personal privacy and security.

## Status

Don't use it. It's not ready; I'll update this document as the project moves along.

Methods supported:

 * sodium_version_string
 * crypto_hash
 * crypto_hash_sha512
 * crypto_hash_sha256
 * crypto_generichash
 * crypto_shorthash
 * crypto_secretbox
 * crypto_secretbox_open

## Requirements & Versions

This library is built in Visual Studio 2010, and targets .NET 4.0; it is compiled against libsodium v0.4.3.

## Notes

Any method that takes a String, has an overload that accepts a byte array; Strings are assumed to be UTF8; if this is not the case, please convert it to bytes yourself and use the overloads that accept byte arrays.

## License

NaCl has been released to the public domain to avoid copyright issues. libsodium is subject to the [ISC license](https://en.wikipedia.org/wiki/ISC_license), and this software is subject to the MIT license (see LICENSE).

# libsodium-net
libsodium-net, or better said, [libsodium](https://github.com/jedisct1/libsodium) for .NET, is a C# wrapper around libsodium. For those that don't know, libsodium is a portable implementation of [Daniel Bernstein's](http://cr.yp.to/djb.html) fantastic [NaCl](http://nacl.cr.yp.to/) library. If you aren't familiar with NaCl, you should probably do some reading before using this library.

## Why

NaCl is a great library in that its designed has made the right choices on what to implement and how - something most developers don't know how to do. So by using it (or a wrapper), many of those details are abstracted away where you don't need to worry about them. NaCl itself is less than portable C, only targeted for *nix systems; libsodium solves this by making it portable and making a few minor changes to better suite being distributed as a compiled binary.

## No really, why?

Crypto is hard - much harder than your average developer understands. There is much going on in the world today, privacy is at risk like never before - many complain, few act. To avoid falling into the complainers group, I've started this effort to make these tools readily available to the .NET community in hopes they will be used to further the goals of defending personal privacy and security.

## Status

Experimental. This is still a work in progress, as such the API is subject to change and there may be bugs that have been missed.

## Methods Supported

The following methods have been implemented and have at least basic unit tests in place to ensure they are producing the expected output. *(Listed in no particular order)*

#### sodium_version_string
`Sodium.SodiumVersion.SodiumVersionString()` - This returns the version string on the `libsodium` library in use. Note, this is not the version of libsodium-net.

#### crypto_hash
`Sodium.CryptoHash.Hash()` - This hashes a message (UTF-8 encoded `string` or `byte[]`) using the default algorithm, currently SHA-512. A byte array is returned.

The `Sodium.CryptoHash` class also includes the following methods:

 * `SHA512()` - Compute a SHA-512 hash (for compatibility if the default algorithm is ever changed). (`crypto_hash_sha512`)
 * `SHA256()` - Compute a SHA-256 hash. (`crypto_hash_sha256 `)

#### crypto_generichash
`Sodium.GenericHash.Hash()` - This is a multi-purpose fast hash, that has variable output size and an optional key. As with the `CryptoHash` methods, the input can be a UTF-8 encoded string, or a byte array, and a byte array is returned. 

This is the most flexible hashing option; and the one I would recommend the most.

This is currently based on [BLAKE2b](https://blake2.net/), and has the following properties:

 * Variable output from 16 to 64 bytes.
 * Optional keyed mode, accepting a key from 16 to 64 bytes.

Note: Only libsodium's simplified interface is currently supported; the streaming interface is not implemented at this time. 

#### crypto_shorthash
`Sodium.ShortHash.Hash()` - Short, high-speed hashing, currently implanted via [SipHash-2-4](https://en.wikipedia.org/wiki/SipHash) and produces an 8 byte hash.

#### crypto_secretbox
`Sodium.SecretBox.Create()` - This method encrypts and authenticates a message. This is currently implemented via [Salsa20](https://en.wikipedia.org/wiki/Salsa20) and [Poly1305](https://en.wikipedia.org/wiki/Poly1305).

Details:

 * Key length: 32 bytes
 * Nonce length: 24 bytes

Note: As in any crypto system, it's important to avoid reusing a nonce, so the nonce should either be randomly generated or consist of a non-repeatable message ID. To minimize risks, my recommendation is to randomly generate the nonce.

#### crypto_secretbox_open
`Sodium.SecretBox.Open()` - This method retrieves the message encrypted via `SecretBox.Create()`. To decrypt and authenticate the data, you pass the key, nonce, and cipher text; if there is an issue decrypting the message, you will receive a generic `CryptographicException` - the exact reason for the failure isn't provided.

## Requirements & Versions

This library is built in Visual Studio 2010, and targets .NET 4.0; it is compiled against libsodium v0.4.3.

## Notes

Any method that takes a String, has an overload that accepts a byte array; Strings are assumed to be UTF8; if this is not the case, please convert it to bytes yourself and use the overloads that accept byte arrays.

## License

NaCl has been released to the public domain to avoid copyright issues. libsodium is subject to the [ISC license](https://en.wikipedia.org/wiki/ISC_license), and this software is subject to the MIT license (see LICENSE).

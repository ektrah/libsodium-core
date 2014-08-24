# libsodium-net [![Build Status](https://travis-ci.org/adamcaudill/libsodium-net.svg?branch=master)](https://travis-ci.org/adamcaudill/libsodium-net)
libsodium-net, or better said, [libsodium](https://github.com/jedisct1/libsodium) for .NET, is a C# wrapper around libsodium. For those that don't know, libsodium is a portable implementation of [Daniel Bernstein's](http://cr.yp.to/djb.html) fantastic [NaCl](http://nacl.cr.yp.to/) library. If you aren't familiar with NaCl, I highly suggest that you look into libsodium and NaCl before using this library.

Want to support development? Consider donating via Bitcoin to `14jumFDmuVkLiAt4TgyKt17SWHtPRbkcLr` - all donations, no matter how small are appreciated.

## Why

NaCl is a great library in that its designed has made the right choices on what to implement and how - something most developers don't know how to do. So by using it (or a wrapper), many of those details are abstracted away where you don't need to worry about them. NaCl itself is less than portable C, only targeted for *nix systems; libsodium solves this by making it portable and making a few minor changes to better suite being distributed as a compiled binary.

## No really, why?

Crypto is hard - much harder than your average developer understands. There is much going on in the world today, privacy is at risk like never before - many complain, few act. To avoid falling into the complainers group, I've started this effort to make these tools readily available to the .NET community in hopes they will be used to further the goals of defending personal privacy and security.

## Status

TL;DR: Experimental. 

This is still a work in progress, as such the API is subject to change and there may be bugs that have been missed. Currently, not all of libsodium is implemented; though the most used methods should be; if there's anything that you need that libsodium supports that this library doesn't, please open an issue - or better, open a pull request.

## Installation

**Windows**: For Windows, the `libsodium` library is included in the [release](https://github.com/adamcaudill/libsodium-net/releases) packages. Just download the correct version for your platform (x84 or x64; there's no universal version, sorry).

**OSX**: For OSX, `libsodium-net` can easily be built in Xamarin Studio, and `libsodium` can be installed easily via `brew`:

    brew install libsodium --universal

**Linux**: As with OSX, building with Xamarin Studio is simple, or there's always the option of using `xbuild`:

    xbuild libsodium-net.sln

For `libsodium`, many package managers provide older versions, so it's recommended to build the latest version from source. Thankfully, this is a fairly painless process. See the [travis-build-libsodium.sh](https://github.com/adamcaudill/libsodium-net/blob/master/travis-build-libsodium.sh) file or the `libsodium` [README](https://github.com/jedisct1/libsodium/blob/master/README.markdown) file for details.

**Other**: Support for other Mono supported platforms hasn't been determined. It may or may not work.

Note: For all platforms, it's critical that `libsodium` be compiled for the architecture that the process is running under. If they don't match, you can expect to see errors. If your process is x86/i386, you can't use a copy of `libsodium` compiled for x64.

## Methods Supported

The following methods have been implemented and have at least basic unit tests in place to ensure they are producing the expected output. *(Listed in no particular order)*

### Asymmetric

#### crypto_sign_keypair
`Sodium.PublicKeyAuth.GenerateKeyPair()` - Generates a public/private [Ed25519](http://ed25519.cr.yp.to/) key pair based on a random seed. The public key is 32 bytes, the private key is 64 bytes.

#### crypto_sign_seed_keypair
`Sodium.PublicKeyAuth.GenerateKeyPair()` - Generates a public/private [Ed25519](http://ed25519.cr.yp.to/) key pair based on the provided seed to allow deterministic key generation. The public key is 32 bytes, the private key is 64 bytes, seed must be 32 bytes.

#### crypto_sign
`Sodium.PublicKeyAuth.Sign()` - Signs a message with [Ed25519](http://ed25519.cr.yp.to/), based on the supplied 64 byte private key.

#### crypto_sign_open
`Sodium.PublicKeyAuth.Verify()` - Verifies the signature and returns the clear-text message using [Ed25519](http://ed25519.cr.yp.to/) and the supplied 32-byte public key. Throws a `CryptographicException` if verification fails.

#### crypto_box_keypair
`Sodium.PublicKeyBox.GenerateKeyPair()` - Generates a public/private Curve25519-XSalsa20-Poly1305 key pair based on a random seed. The public key is 32 bytes, the private key is 32 bytes.

#### crypto_box
`Sodium.PublicKeyBox.Create()` - Encrypts a message using the sender's private key, and the recipient's public key. Both keys are 32 bytes. Encryption / signing is performed via Curve25519-XSalsa20-Poly1305.

#### crypto_box_open
`Sodium.PublicKeyBox.Open()` - Decrypts and verifies the sender's signature using the recipient's private key and the sender's public key. Both keys are 32 bytes. Throws a `CryptographicException` if verification fails.

### Symmetric

#### crypto_secretbox
`Sodium.SecretBox.Create()` - This method encrypts and authenticates a message. This is currently implemented via [XSalsa20](https://en.wikipedia.org/wiki/Salsa20) and [Poly1305](https://en.wikipedia.org/wiki/Poly1305).

Details:

 * Key length: 32 bytes
 * Nonce length: 24 bytes

Note: As in any crypto system, it's important to avoid reusing a nonce, so the nonce should either be randomly generated or consist of a non-repeatable message ID. To minimize risks, my recommendation is to randomly generate the nonce.

#### crypto_secretbox_open
`Sodium.SecretBox.Open()` - This method retrieves the message encrypted via `SecretBox.Create()`. To decrypt and authenticate the data, you pass the key, nonce, and cipher text; if there is an issue decrypting the message, you will receive a generic `CryptographicException` - the exact reason for the failure isn't provided.

#### crypto_onetimeauth
`Sodium.OneTimeAuth.Sign()` - Provides messages authentication via [Poly1305](https://en.wikipedia.org/wiki/Poly1305). The method takes a messages (as UTF-8 string or byte array), a 32 byte key (that must be used only once), and returns a 16 bytes signature.

For this to be secure, it's required that the signing key only be used once.

#### crypto_onetimeauth_verify
`Sodium.OneTimeAuth.Verify()` - This verifies a signature generated via `crypto_onetimeauth`. To do so, it requires the original message, the 16 byte signature, and the 32 byte key.

#### crypto_auth
`Sodium.SecretKeyAuth.Sign()` - Provides messages authentication via HMAC-SHA512-256. The method takes a messages (as UTF-8 string or byte array), a 32 byte key, and returns a 32 bytes signature.

#### crypto_auth_verify
`Sodium.SecretKeyAuth.Verify()` - This verifies a signature generated via `crypto_auth`. To do so, it requires the original message, the 32 byte signature, and the 32 byte key.

#### crypto_stream_xor
`Sodium.StreamEncryption.Encrypt()` - Encrypts a message via XSalsa20 using a 32 byte key and a 24 byte nonce. As always, it's critical that the nonce never be reused. This provides encryption only, not authentication.

`Sodium.StreamEncryption.Decrypt()` - Decrypts messages via XSalsa20.

### Hashing

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

#### crypto_generichash_blake2b_salt_personal
`Sodium.GenericHash.HashSaltPersonal()` - Hash with salt, personal and optional key.

#### crypto_pwhash_scryptsalsa208sha256_str
`Sodium.PasswordHash.HashSalsa208Sha256()` - Returns the hash is a string format, which includes the generated salt.

#### crypto_pwhash_scryptsalsa208sha256_str_verify
`Sodium.PasswordHash.HashSalsa208Sha256Verify()` - Verifies that a hash generated with `HashSalsa208Sha256` matches the supplied password.

### Other

#### sodium_version_string
`Sodium.SodiumCore.SodiumVersionString()` - This returns the version string on the `libsodium` library in use. Note, this is not the version of libsodium-net.

#### randombytes_buf
`Sodium.SodiumCore.GetRandomBytes()` - Gets a number of random bytes, suitable for use as a key or nonce. In classes where appropriate, there are `GenerateKey()` and/or `GenerateNonce()` functions that return a byte array of the correct size.

#### crypto_scalarmult
`Sodium.ScalarMult.Mult` (and related methods) - Provides an interface to perform scalar multiplication.

### Non-libsodium Methods

There are a small number of additional methods that extended or simplify the usage of this library.

#### HexToBinary
`Sodium.Utilities.HexToBinary()` - This method converts a lower-case hex-encoded string to a byte array.

#### BinaryToHex
`Sodium.Utilities.BinaryToHex()` - This method takes a byte array, and produces a lower-case hex-encoded string.

## Requirements & Versions

This library can be built in Visual Studio 2010, Xamarin Studio (MonoDevelop 3.x supported), and targets .NET 4.0; it is compiled against libsodium v0.7.0.

On OSX & Linux, your copy of `libsodium` must be compiled for the same architecture as your copy of Mono. If you are running a 32bit process, your copy of `libsodium` must be 32bit as well.

## Notes

Any method that takes a String, has an overload that accepts a byte array; Strings are assumed to be UTF8; if this is not the case, please convert it to bytes yourself and use the overloads that accept byte arrays.

## File Signing

Starting with version 0.3.0, all files are GPG signed to simplify validation. Files are signed with key ID `0x22CAD57A659CA2BC`, fingerprint: `E88AA5A5EB1162B8CAE0A52422CAD57A659CA2BC`. You can find the key on [pgp.mit.edu](https://pgp.mit.edu/pks/lookup?search=0x22CAD57A659CA2BC) or on my [personal web site](https://adamcaudill.com/pgp/).

## License

NaCl has been released to the public domain to avoid copyright issues. libsodium is subject to the [ISC license](https://en.wikipedia.org/wiki/ISC_license), and this software is subject to the MIT license (see LICENSE).

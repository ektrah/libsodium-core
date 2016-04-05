using System;
using System.Runtime.InteropServices;

namespace Sodium
{
  /// <summary>
  /// libsodium library binding.
  /// </summary>
  public static class SodiumLibrary
  {
    internal static bool IsRunningOnMono
    {
      get
      {
        return Type.GetType("Mono.Runtime") != null;
      }
    }

    internal static bool Is64
    {
      get
      {
        return IntPtr.Size == 8;
      }
    }

    internal static string Name
    {
      get
      {
        const string LIBRARY_X86 = "libsodium.dll";
        const string LIBRARY_X64 = "libsodium-64.dll";
        const string LIBRARY_MONO = "libsodium";

        var lib = Is64 ? LIBRARY_X64 : LIBRARY_X86;

        //if we're on mono, override
        if (IsRunningOnMono)
          lib = LIBRARY_MONO;

        return lib;
      }
    }

    //init
    internal delegate void _Init();
    internal static LazyInvoke<_Init> _init = new LazyInvoke<_Init>("sodium_init", SodiumLibrary.Name);
    internal static _Init init { get { return _init.Method; } }

    //randombytes_buff
    internal delegate void _GetRandomBytes(byte[] buffer, int size);
    internal static LazyInvoke<_GetRandomBytes> _randombytes_buff = new LazyInvoke<_GetRandomBytes>("randombytes_buf", SodiumLibrary.Name);
    internal static _GetRandomBytes randombytes_buff { get { return _randombytes_buff.Method; } }

    //randombytes_uniform
    internal delegate int _GetRandomNumber(int upperBound);
    internal static LazyInvoke<_GetRandomNumber> _randombytes_uniform = new LazyInvoke<_GetRandomNumber>("randombytes_uniform", SodiumLibrary.Name);
    internal static _GetRandomNumber randombytes_uniform { get { return _randombytes_uniform.Method; } }

    //sodium_increment
    internal delegate void _SodiumIncrement(byte[] buffer, long length);
    internal static LazyInvoke<_SodiumIncrement> _sodium_increment = new LazyInvoke<_SodiumIncrement>("sodium_increment", SodiumLibrary.Name);
    internal static _SodiumIncrement sodium_increment { get { return _sodium_increment.Method; } }

    //sodium_compare
    internal delegate int _SodiumCompare(byte[] a, byte[] b, long length);
    internal static LazyInvoke<_SodiumCompare> _sodium_compare = new LazyInvoke<_SodiumCompare>("sodium_compare", SodiumLibrary.Name);
    internal static _SodiumCompare sodium_compare { get { return _sodium_compare.Method; } }

    //sodium_version_string
    internal delegate IntPtr _SodiumVersionString();
    internal static LazyInvoke<_SodiumVersionString> _sodium_version_string = new LazyInvoke<_SodiumVersionString>("sodium_version_string", SodiumLibrary.Name);
    internal static _SodiumVersionString sodium_version_string { get { return _sodium_version_string.Method; } }

    //crypto_hash
    internal delegate int _CryptoHash(byte[] buffer, byte[] message, long length);
    internal static LazyInvoke<_CryptoHash> _crypto_hash = new LazyInvoke<_CryptoHash>("crypto_hash", SodiumLibrary.Name);
    internal static _CryptoHash crypto_hash { get { return _crypto_hash.Method; } }

    //crypto_hash_sha512
    internal delegate int _Sha512(byte[] buffer, byte[] message, long length);
    internal static LazyInvoke<_Sha512> _crypto_hash_sha512 = new LazyInvoke<_Sha512>("crypto_hash_sha512", SodiumLibrary.Name);
    internal static _Sha512 crypto_hash_sha512 { get { return _crypto_hash_sha512.Method; } }

    //crypto_hash_sha256
    internal delegate int _Sha256(byte[] buffer, byte[] message, long length);
    internal static LazyInvoke<_Sha256> _crypto_hash_sha256 = new LazyInvoke<_Sha256>("crypto_hash_sha256", SodiumLibrary.Name);
    internal static _Sha256 crypto_hash_sha256 { get { return _crypto_hash_sha256.Method; } }

    //crypto_generichash
    internal delegate int _GenericHash(byte[] buffer, int bufferLength, byte[] message, long messageLength, byte[] key, int keyLength);
    internal static LazyInvoke<_GenericHash> _crypto_generichash = new LazyInvoke<_GenericHash>("crypto_generichash", SodiumLibrary.Name);
    internal static _GenericHash crypto_generichash { get { return _crypto_generichash.Method; } }

    //crypto_generichash_blake2b_salt_personal
    internal delegate int _GenericHashSaltPersonal(byte[] buffer, int bufferLength, byte[] message, long messageLength, byte[] key, int keyLength, byte[] salt, byte[] personal);
    internal static LazyInvoke<_GenericHashSaltPersonal> _crypto_generichash_blake2b_salt_personal = new LazyInvoke<_GenericHashSaltPersonal>("crypto_generichash_blake2b_salt_personal", SodiumLibrary.Name);
    internal static _GenericHashSaltPersonal crypto_generichash_blake2b_salt_personal { get { return _crypto_generichash_blake2b_salt_personal.Method; } }

    //crypto_onetimeauth
    internal delegate int _OneTimeSign(byte[] buffer, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_OneTimeSign> _crypto_onetimeauth = new LazyInvoke<_OneTimeSign>("crypto_onetimeauth", SodiumLibrary.Name);
    internal static _OneTimeSign crypto_onetimeauth { get { return _crypto_onetimeauth.Method; } }

    //crypto_onetimeauth_verify
    internal delegate int _OneTimeVerify(byte[] signature, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_OneTimeVerify> _crypto_onetimeauth_verify = new LazyInvoke<_OneTimeVerify>("crypto_onetimeauth_verify", SodiumLibrary.Name);
    internal static _OneTimeVerify crypto_onetimeauth_verify { get { return _crypto_onetimeauth_verify.Method; } }

    //crypto_pwhash_str
    internal delegate int _ArgonHashString(byte[] buffer, byte[] password, long passwordLen, long opsLimit, int memLimit);
    internal static LazyInvoke<_ArgonHashString> _crypto_pwhash_str = new LazyInvoke<_ArgonHashString>("crypto_pwhash_argon2i_str", SodiumLibrary.Name);
    internal static _ArgonHashString crypto_pwhash_str { get { return _crypto_pwhash_str.Method; } }

    //crypto_pwhash_str_verify
    internal delegate int _ArgonHashVerify(byte[] buffer, byte[] password, long passLength);
    internal static LazyInvoke<_ArgonHashVerify> _crypto_pwhash_str_verify = new LazyInvoke<_ArgonHashVerify>("crypto_pwhash_argon2i_str_verify", SodiumLibrary.Name);
    internal static _ArgonHashVerify crypto_pwhash_str_verify { get { return _crypto_pwhash_str_verify.Method; } }

    //crypto_pwhash
    internal delegate int _ArgonHashBinary(byte[] buffer, long bufferLen, byte[] password, long passwordLen, byte[] salt, long opsLimit, int memLimit, int alg);
    internal static LazyInvoke<_ArgonHashBinary> _crypto_pwhash = new LazyInvoke<_ArgonHashBinary>("crypto_pwhash_argon2i", SodiumLibrary.Name);
    internal static _ArgonHashBinary crypto_pwhash { get { return _crypto_pwhash.Method; } }

    //crypto_pwhash_scryptsalsa208sha256_str
    internal delegate int _HashString(byte[] buffer, byte[] password, long passwordLen, long opsLimit, int memLimit);
    internal static LazyInvoke<_HashString> _crypto_pwhash_scryptsalsa208sha256_str = new LazyInvoke<_HashString>("crypto_pwhash_scryptsalsa208sha256_str", SodiumLibrary.Name);
    internal static _HashString crypto_pwhash_scryptsalsa208sha256_str { get { return _crypto_pwhash_scryptsalsa208sha256_str.Method; } }

    //crypto_pwhash_scryptsalsa208sha256
    internal delegate int _HashBinary(byte[] buffer, long bufferLen, byte[] password, long passwordLen, byte[] salt, long opsLimit, int memLimit);
    internal static LazyInvoke<_HashBinary> _crypto_pwhash_scryptsalsa208sha256 = new LazyInvoke<_HashBinary>("crypto_pwhash_scryptsalsa208sha256", SodiumLibrary.Name);
    internal static _HashBinary crypto_pwhash_scryptsalsa208sha256 { get { return _crypto_pwhash_scryptsalsa208sha256.Method; } }

    //crypto_pwhash_scryptsalsa208sha256_str_verify
    internal delegate int _HashVerify(byte[] buffer, byte[] password, long passLength);
    internal static LazyInvoke<_HashVerify> _crypto_pwhash_scryptsalsa208sha256_str_verify = new LazyInvoke<_HashVerify>("crypto_pwhash_scryptsalsa208sha256_str_verify", SodiumLibrary.Name);
    internal static _HashVerify crypto_pwhash_scryptsalsa208sha256_str_verify { get { return _crypto_pwhash_scryptsalsa208sha256_str_verify.Method; } }

    //crypto_sign_keypair
    internal delegate int _GenerateKeyPair(byte[] publicKey, byte[] secretKey);
    internal static LazyInvoke<_GenerateKeyPair> _crypto_sign_keypair = new LazyInvoke<_GenerateKeyPair>("crypto_sign_keypair", SodiumLibrary.Name);
    internal static _GenerateKeyPair crypto_sign_keypair { get { return _crypto_sign_keypair.Method; } }

    //crypto_sign_seed_keypair
    internal delegate int _GenerateKeyPairFromSeed(byte[] publicKey, byte[] secretKey, byte[] seed);
    internal static LazyInvoke<_GenerateKeyPairFromSeed> _crypto_sign_seed_keypair = new LazyInvoke<_GenerateKeyPairFromSeed>("crypto_sign_seed_keypair", SodiumLibrary.Name);
    internal static _GenerateKeyPairFromSeed crypto_sign_seed_keypair { get { return _crypto_sign_seed_keypair.Method; } }

    //crypto_sign
    internal delegate int _Sign(byte[] buffer, ref long bufferLength, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_Sign> _crypto_sign = new LazyInvoke<_Sign>("crypto_sign", SodiumLibrary.Name);
    internal static _Sign crypto_sign { get { return _crypto_sign.Method; } }

    //crypto_sign_open
    internal delegate int _Verify(byte[] buffer, ref long bufferLength, byte[] signedMessage, long signedMessageLength, byte[] key);
    internal static LazyInvoke<_Verify> _crypto_sign_open = new LazyInvoke<_Verify>("crypto_sign_open", SodiumLibrary.Name);
    internal static _Verify crypto_sign_open { get { return _crypto_sign_open.Method; } }

    //crypto_sign_detached
    internal delegate int _SignDetached(byte[] signature, ref long signatureLength, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_SignDetached> _crypto_sign_detached = new LazyInvoke<_SignDetached>("crypto_sign_detached", SodiumLibrary.Name);
    internal static _SignDetached crypto_sign_detached { get { return _crypto_sign_detached.Method; } }

    //crypto_sign_verify_detached
    internal delegate int _VerifyDetached(byte[] signature, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_VerifyDetached> _crypto_sign_verify_detached = new LazyInvoke<_VerifyDetached>("crypto_sign_verify_detached", SodiumLibrary.Name);
    internal static _VerifyDetached crypto_sign_verify_detached { get { return _crypto_sign_verify_detached.Method; } }

    //crypto_sign_ed25519_sk_to_seed
    internal delegate int _Ed25519SecretKeyToEd25519Seed(byte[] seed, byte[] secretKey);
    internal static LazyInvoke<_Ed25519SecretKeyToEd25519Seed> _crypto_sign_ed25519_sk_to_seed = new LazyInvoke<_Ed25519SecretKeyToEd25519Seed>("crypto_sign_ed25519_sk_to_seed", SodiumLibrary.Name);
    internal static _Ed25519SecretKeyToEd25519Seed crypto_sign_ed25519_sk_to_seed { get { return _crypto_sign_ed25519_sk_to_seed.Method; } }

    //crypto_sign_ed25519_sk_to_pk
    internal delegate int _Ed25519SecretKeyToEd25519PublicKey(byte[] publicKey, byte[] secretKey);
    internal static LazyInvoke<_Ed25519SecretKeyToEd25519PublicKey> _crypto_sign_ed25519_sk_to_pk = new LazyInvoke<_Ed25519SecretKeyToEd25519PublicKey>("crypto_sign_ed25519_sk_to_pk", SodiumLibrary.Name);
    internal static _Ed25519SecretKeyToEd25519PublicKey crypto_sign_ed25519_sk_to_pk { get { return _crypto_sign_ed25519_sk_to_pk.Method; } }

    //crypto_sign_ed25519_pk_to_curve25519
    internal delegate int _Ed25519PublicKeyToCurve25519PublicKey(byte[] curve25519Pk, byte[] ed25519Pk);
    internal static LazyInvoke<_Ed25519PublicKeyToCurve25519PublicKey> _crypto_sign_ed25519_pk_to_curve25519 = new LazyInvoke<_Ed25519PublicKeyToCurve25519PublicKey>("crypto_sign_ed25519_pk_to_curve25519", SodiumLibrary.Name);
    internal static _Ed25519PublicKeyToCurve25519PublicKey crypto_sign_ed25519_pk_to_curve25519 { get { return _crypto_sign_ed25519_pk_to_curve25519.Method; } }

    //crypto_sign_ed25519_sk_to_curve25519
    internal delegate int _Ed25519SecretKeyToCurve25519SecretKey(byte[] curve25519Sk, byte[] ed25519Sk);
    internal static LazyInvoke<_Ed25519SecretKeyToCurve25519SecretKey> _crypto_sign_ed25519_sk_to_curve25519 = new LazyInvoke<_Ed25519SecretKeyToCurve25519SecretKey>("crypto_sign_ed25519_sk_to_curve25519", SodiumLibrary.Name);
    internal static _Ed25519SecretKeyToCurve25519SecretKey crypto_sign_ed25519_sk_to_curve25519 { get { return _crypto_sign_ed25519_sk_to_curve25519.Method; } }

    //crypto_box_keypair
    internal delegate int _GenerateBoxKeyPair(byte[] publicKey, byte[] secretKey);
    internal static LazyInvoke<_GenerateBoxKeyPair> _crypto_box_keypair = new LazyInvoke<_GenerateBoxKeyPair>("crypto_box_keypair", SodiumLibrary.Name);
    internal static _GenerateBoxKeyPair crypto_box_keypair { get { return _crypto_box_keypair.Method; } }

    //crypto_box_easy
    internal delegate int _Create(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] publicKey, byte[] secretKey);
    internal static LazyInvoke<_Create> _crypto_box_easy = new LazyInvoke<_Create>("crypto_box_easy", SodiumLibrary.Name);
    internal static _Create crypto_box_easy { get { return _crypto_box_easy.Method; } }

    //crypto_box_open_easy
    internal delegate int _Open(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] publicKey, byte[] secretKey);
    internal static LazyInvoke<_CreateDetached> _crypto_box_detached = new LazyInvoke<_CreateDetached>("crypto_box_detached", SodiumLibrary.Name);
    internal static _CreateDetached crypto_box_detached { get { return _crypto_box_detached.Method; } }

    //crypto_box_detached
    internal delegate int _CreateDetached(byte[] cipher, byte[] mac, byte[] message, long messageLength, byte[] nonce, byte[] pk, byte[] sk);
    internal static LazyInvoke<_Open> _crypto_box_open_easy = new LazyInvoke<_Open>("crypto_box_open_easy", SodiumLibrary.Name);
    internal static _Open crypto_box_open_easy { get { return _crypto_box_open_easy.Method; } }

    //crypto_box_open_detached
    internal delegate int _OpenDetached(byte[] buffer, byte[] cipherText, byte[] mac, long cipherTextLength, byte[] nonce, byte[] pk, byte[] sk);
    internal static LazyInvoke<_OpenDetached> _crypto_box_open_detached = new LazyInvoke<_OpenDetached>("crypto_box_open_detached", SodiumLibrary.Name);
    internal static _OpenDetached crypto_box_open_detached { get { return _crypto_box_open_detached.Method; } }

    //crypto_scalarmult_bytes
    internal delegate int _Bytes();
    internal static LazyInvoke<_Bytes> _crypto_scalarmult_bytes = new LazyInvoke<_Bytes>("crypto_scalarmult_bytes", SodiumLibrary.Name);
    internal static _Bytes crypto_scalarmult_bytes { get { return _crypto_scalarmult_bytes.Method; } }

    //crypto_scalarmult_scalarbytes
    internal delegate int _ScalarBytes();
    internal static LazyInvoke<_ScalarBytes> _crypto_scalarmult_scalarbytes = new LazyInvoke<_ScalarBytes>("crypto_scalarmult_scalarbytes", SodiumLibrary.Name);
    internal static _ScalarBytes crypto_scalarmult_scalarbytes { get { return _crypto_scalarmult_scalarbytes.Method; } }

    //crypto_scalarmult_primitive
    internal delegate byte _Primitive();
    internal static LazyInvoke<_Primitive> _crypto_scalarmult_primitive = new LazyInvoke<_Primitive>("crypto_scalarmult_primitive", SodiumLibrary.Name);
    internal static _Primitive crypto_scalarmult_primitive { get { return _crypto_scalarmult_primitive.Method; } }

    //crypto_scalarmult_base
    internal delegate int _Base(byte[] q, byte[] n);
    internal static LazyInvoke<_Base> _crypto_scalarmult_base = new LazyInvoke<_Base>("crypto_scalarmult_base", SodiumLibrary.Name);
    internal static _Base crypto_scalarmult_base { get { return _crypto_scalarmult_base.Method; } }

    //crypto_scalarmult
    internal delegate int _ScalarMult(byte[] q, byte[] n, byte[] p);
    internal static LazyInvoke<_ScalarMult> _crypto_scalarmult = new LazyInvoke<_ScalarMult>("crypto_scalarmult", SodiumLibrary.Name);
    internal static _ScalarMult crypto_scalarmult { get { return _crypto_scalarmult.Method; } }

    //crypto_box_seal
    internal delegate int _CreateSeal(byte[] buffer, byte[] message, long messageLength, byte[] pk);
    internal static LazyInvoke<_CreateSeal> _crypto_box_seal = new LazyInvoke<_CreateSeal>("crypto_box_seal", SodiumLibrary.Name);
    internal static _CreateSeal crypto_box_seal { get { return _crypto_box_seal.Method; } }

    //crypto_box_seal_open
    internal delegate int _OpenSeal(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] pk, byte[] sk);
    internal static LazyInvoke<_OpenSeal> _crypto_box_seal_open = new LazyInvoke<_OpenSeal>("crypto_box_seal_open", SodiumLibrary.Name);
    internal static _OpenSeal crypto_box_seal_open { get { return _crypto_box_seal_open.Method; } }

    //crypto_secretbox
    internal delegate int _CreateSecret(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
    internal static LazyInvoke<_CreateSecret> _crypto_secretbox = new LazyInvoke<_CreateSecret>("crypto_secretbox", SodiumLibrary.Name);
    internal static _CreateSecret crypto_secretbox { get { return _crypto_secretbox.Method; } }

    //crypto_secretbox_open
    internal delegate int _OpenSecret(byte[] buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] key);
    internal static LazyInvoke<_OpenSecret> _crypto_secretbox_open = new LazyInvoke<_OpenSecret>("crypto_secretbox_open", SodiumLibrary.Name);
    internal static _OpenSecret crypto_secretbox_open { get { return _crypto_secretbox_open.Method; } }

    //crypto_secretbox_detached
    internal delegate int _CreateSecretDetached(byte[] cipher, byte[] mac, byte[] message, long messageLength, byte[] nonce, byte[] key);
    internal static LazyInvoke<_CreateSecretDetached> _crypto_secretbox_detached = new LazyInvoke<_CreateSecretDetached>("crypto_secretbox_detached", SodiumLibrary.Name);
    internal static _CreateSecretDetached crypto_secretbox_detached { get { return _crypto_secretbox_detached.Method; } }

    //crypto_secretbox_open_detached
    internal delegate int _OpenSecretDetached(byte[] buffer, byte[] cipherText, byte[] mac, long cipherTextLength, byte[] nonce, byte[] key);
    internal static LazyInvoke<_OpenSecretDetached> _crypto_secretbox_open_detached = new LazyInvoke<_OpenSecretDetached>("crypto_secretbox_open_detached", SodiumLibrary.Name);
    internal static _OpenSecretDetached crypto_secretbox_open_detached { get { return _crypto_secretbox_open_detached.Method; } }

    //crypto_auth
    internal delegate int _Auth(byte[] buffer, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_Auth> _crypto_auth = new LazyInvoke<_Auth>("crypto_auth", SodiumLibrary.Name);
    internal static _Auth crypto_auth { get { return _crypto_auth.Method; } }

    //crypto_auth_verify
    internal delegate int _VerifyAuth(byte[] signature, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_VerifyAuth> _crypto_auth_verify = new LazyInvoke<_VerifyAuth>("crypto_auth_verify", SodiumLibrary.Name);
    internal static _VerifyAuth crypto_auth_verify { get { return _crypto_auth_verify.Method; } }

    //crypto_auth_hmacsha256
    internal delegate int _HmacSha256(byte[] buffer, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_HmacSha256> _crypto_auth_hmacsha256 = new LazyInvoke<_HmacSha256>("crypto_auth_hmacsha256", SodiumLibrary.Name);
    internal static _HmacSha256 crypto_auth_hmacsha256 { get { return _crypto_auth_hmacsha256.Method; } }

    //crypto_auth_hmacsha256_verify
    internal delegate int _HmacSha256Verify(byte[] signature, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_HmacSha256Verify> _crypto_auth_hmacsha256_verify = new LazyInvoke<_HmacSha256Verify>("crypto_auth_hmacsha256_verify", SodiumLibrary.Name);
    internal static _HmacSha256Verify crypto_auth_hmacsha256_verify { get { return _crypto_auth_hmacsha256_verify.Method; } }

    //crypto_auth_hmacsha512
    internal delegate int _HmacSha512(byte[] signature, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_HmacSha512> _crypto_auth_hmacsha512 = new LazyInvoke<_HmacSha512>("crypto_auth_hmacsha512", SodiumLibrary.Name);
    internal static _HmacSha512 crypto_auth_hmacsha512 { get { return _crypto_auth_hmacsha512.Method; } }

    //crypto_auth_hmacsha512_verify
    internal delegate int _HmacSha512Verify(byte[] signature, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_HmacSha512Verify> _crypto_auth_hmacsha512_verify = new LazyInvoke<_HmacSha512Verify>("crypto_auth_hmacsha512_verify", SodiumLibrary.Name);
    internal static _HmacSha512Verify crypto_auth_hmacsha512_verify { get { return _crypto_auth_hmacsha512_verify.Method; } }

    //crypto_shorthash
    internal delegate int _ShortHash(byte[] buffer, byte[] message, long messageLength, byte[] key);
    internal static LazyInvoke<_ShortHash> _crypto_shorthash = new LazyInvoke<_ShortHash>("crypto_shorthash", SodiumLibrary.Name);
    internal static _ShortHash crypto_shorthash { get { return _crypto_shorthash.Method; } }

    //crypto_stream_xor
    internal delegate int _Encrypt(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
    internal static LazyInvoke<_Encrypt> _crypto_stream_xor = new LazyInvoke<_Encrypt>("crypto_stream_xor", SodiumLibrary.Name);
    internal static _Encrypt crypto_stream_xor { get { return _crypto_stream_xor.Method; } }

    //crypto_stream_chacha20_xor
    internal delegate int _EncryptChaCha20(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);
    internal static LazyInvoke<_EncryptChaCha20> _crypto_stream_chacha20_xor = new LazyInvoke<_EncryptChaCha20>("crypto_stream_chacha20_xor", SodiumLibrary.Name);
    internal static _EncryptChaCha20 crypto_stream_chacha20_xor { get { return _crypto_stream_chacha20_xor.Method; } }

    //sodium_bin2hex
    internal delegate IntPtr _Bin2Hex(byte[] hex, int hexMaxlen, byte[] bin, int binLen);
    internal static LazyInvoke<_Bin2Hex> _sodium_bin2hex = new LazyInvoke<_Bin2Hex>("sodium_bin2hex", SodiumLibrary.Name);
    internal static _Bin2Hex sodium_bin2hex { get { return _sodium_bin2hex.Method; } }

    //sodium_hex2bin
    internal delegate int _Hex2Bin(IntPtr bin, int binMaxlen, string hex, int hexLen, string ignore, out int binLen, string hexEnd);
    internal static LazyInvoke<_Hex2Bin> _sodium_hex2bin = new LazyInvoke<_Hex2Bin>("sodium_hex2bin", SodiumLibrary.Name);
    internal static _Hex2Bin sodium_hex2bin { get { return _sodium_hex2bin.Method; } }

    //crypto_aead_chacha20poly1305_encrypt
    internal delegate int _EncryptAead(
      IntPtr cipher, out long cipherLength, byte[] message, long messageLength, byte[] additionalData,
      long additionalDataLength, byte[] nsec, byte[] nonce, byte[] key);
    internal static LazyInvoke<_EncryptAead> _crypto_aead_chacha20poly1305_encrypt = new LazyInvoke<_EncryptAead>("crypto_aead_chacha20poly1305_encrypt", SodiumLibrary.Name);
    internal static _EncryptAead crypto_aead_chacha20poly1305_encrypt { get { return _crypto_aead_chacha20poly1305_encrypt.Method; } }

    //crypto_aead_chacha20poly1305_decrypt
    internal delegate int _DecryptAead(
      IntPtr message, out long messageLength, byte[] nsec, byte[] cipher, long cipherLength, byte[] additionalData,
      long additionalDataLength, byte[] nonce, byte[] key);
    internal static LazyInvoke<_DecryptAead> _crypto_aead_chacha20poly1305_decrypt = new LazyInvoke<_DecryptAead>("crypto_aead_chacha20poly1305_decrypt", SodiumLibrary.Name);
    internal static _DecryptAead crypto_aead_chacha20poly1305_decrypt { get { return _crypto_aead_chacha20poly1305_decrypt.Method; } }

    //crypto_aead_aes256gcm_is_available
    internal delegate int _AesAvailable();
    internal static LazyInvoke<_AesAvailable> _crypto_aead_aes256gcm_is_available = new LazyInvoke<_AesAvailable>("crypto_aead_aes256gcm_is_available", SodiumLibrary.Name);
    internal static _AesAvailable crypto_aead_aes256gcm_is_available { get { return _crypto_aead_aes256gcm_is_available.Method; } }

    //crypto_aead_aes256gcm_encrypt
    internal delegate int _AesEncrypt(
        IntPtr cipher, out long cipherLength, byte[] message, long messageLength, byte[] additionalData,
        long additionalDataLength, byte[] nsec, byte[] nonce, byte[] key);
    internal static LazyInvoke<_AesEncrypt> _crypto_aead_aes256gcm_encrypt = new LazyInvoke<_AesEncrypt>("crypto_aead_aes256gcm_encrypt", SodiumLibrary.Name);
    internal static _AesEncrypt crypto_aead_aes256gcm_encrypt { get { return _crypto_aead_aes256gcm_encrypt.Method; } }

    //crypto_aead_aes256gcm_decrypt
    internal delegate int _DecryptAes(
        IntPtr message, out long messageLength, byte[] nsec, byte[] cipher, long cipherLength, byte[] additionalData,
        long additionalDataLength, byte[] nonce, byte[] key);
    internal static LazyInvoke<_DecryptAes> _crypto_aead_aes256gcm_decrypt = new LazyInvoke<_DecryptAes>("crypto_aead_aes256gcm_decrypt", SodiumLibrary.Name);
    internal static _DecryptAes crypto_aead_aes256gcm_decrypt { get { return _crypto_aead_aes256gcm_decrypt.Method; } }

    //crypto_generichash_state
    [StructLayout(LayoutKind.Sequential, Size = 384)]
    internal struct _HashState
    {
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
      public ulong[] h;

      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
      public ulong[] t;

      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
      public ulong[] f;

      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
      public byte[] buf;

      public uint buflen;

      public byte last_node;
    }

    //crypto_generichash_init
    internal delegate int _HashInit(IntPtr state, byte[] key, int keySize, int hashSize);
    internal static LazyInvoke<_HashInit> _hash_init = new LazyInvoke<_HashInit>("crypto_generichash_init", SodiumLibrary.Name);
    internal static _HashInit hash_init { get { return _hash_init.Method; } }

    //crypto_generichash_update
    internal delegate int _HashUpdate(IntPtr state, byte[] message, long messageLength);
    internal static LazyInvoke<_HashUpdate> _hash_update = new LazyInvoke<_HashUpdate>("crypto_generichash_update", SodiumLibrary.Name);
    internal static _HashUpdate hash_update { get { return _hash_update.Method; } }

    //crypto_generichash_final
    internal delegate int _HashFinal(IntPtr state, byte[] buffer, int bufferLength);
    internal static LazyInvoke<_HashFinal> _hash_final = new LazyInvoke<_HashFinal>("crypto_generichash_final", SodiumLibrary.Name);
    internal static _HashFinal hash_final { get { return _hash_final.Method; } }
  }
}

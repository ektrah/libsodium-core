using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_generichash_blake2b_BYTES = 32;
        internal const int crypto_generichash_blake2b_BYTES_MAX = 64;
        internal const int crypto_generichash_blake2b_BYTES_MIN = 16;
        internal const int crypto_generichash_blake2b_KEYBYTES = 32;
        internal const int crypto_generichash_blake2b_KEYBYTES_MAX = 64;
        internal const int crypto_generichash_blake2b_KEYBYTES_MIN = 16;
        internal const int crypto_generichash_blake2b_PERSONALBYTES = 16;
        internal const int crypto_generichash_blake2b_SALTBYTES = 16;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_blake2b(
            byte[] @out,
            nuint outlen,
            byte[] @in,
            ulong inlen,
            byte[] key,
            nuint keylen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_blake2b_final(
            ref crypto_generichash_blake2b_state state,
            byte[] @out,
            nuint outlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_blake2b_init(
            ref crypto_generichash_blake2b_state state,
            byte[] key,
            nuint keylen,
            nuint outlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_blake2b_salt_personal(
            byte[] @out,
            nuint outlen,
            byte[] @in,
            ulong inlen,
            byte[] key,
            nuint keylen,
            byte[] salt,
            byte[] personal);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_blake2b_update(
            ref crypto_generichash_blake2b_state state,
            byte[] @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 384)]
        internal struct crypto_generichash_blake2b_state
        {
        }
    }
}

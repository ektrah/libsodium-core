using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_auth_hmacsha256_BYTES = 32;
        internal const int crypto_auth_hmacsha256_KEYBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256(
            byte[] @out,
            byte[] @in,
            ulong inlen,
            byte[] k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_verify(
            byte[] h,
            byte[] @in,
            ulong inlen,
            byte[] k);
    }
}

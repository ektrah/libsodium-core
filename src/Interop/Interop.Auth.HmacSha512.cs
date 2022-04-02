using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_auth_hmacsha512_BYTES = 64;
        internal const int crypto_auth_hmacsha512_KEYBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512(
            byte[] @out,
            byte[] @in,
            ulong inlen,
            byte[] k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_verify(
            byte[] h,
            byte[] @in,
            ulong inlen,
            byte[] k);
    }
}

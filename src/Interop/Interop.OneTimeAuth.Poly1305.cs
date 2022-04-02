using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_onetimeauth_poly1305_BYTES = 16;
        internal const int crypto_onetimeauth_poly1305_KEYBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_poly1305(
            byte[] @out,
            byte[] @in,
            ulong inlen,
            byte[] k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_onetimeauth_poly1305_verify(
            byte[] h,
            byte[] @in,
            ulong inlen,
            byte[] k);
    }
}

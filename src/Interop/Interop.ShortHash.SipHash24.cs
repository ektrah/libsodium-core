using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_shorthash_siphash24_BYTES = 8;
        internal const int crypto_shorthash_siphash24_KEYBYTES = 16;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash_siphash24(
            byte[] @out,
            byte[] @in,
            ulong inlen,
            byte[] k);
    }
}

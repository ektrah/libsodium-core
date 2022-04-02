using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_stream_chacha20_KEYBYTES = 32;
        internal const int crypto_stream_chacha20_NONCEBYTES = 8;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_chacha20_xor(
            byte[] c,
            byte[] m,
            ulong mlen,
            byte[] n,
            byte[] k);
    }
}

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_stream_xchacha20_KEYBYTES = 32;
        internal const int crypto_stream_xchacha20_NONCEBYTES = 24;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_xchacha20_xor(
            byte[] c,
            byte[] m,
            ulong mlen,
            byte[] n,
            byte[] k);
    }
}

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_box_curve25519xsalsa20poly1305_MACBYTES = 16;
        internal const int crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = 24;
        internal const int crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = 32;
        internal const int crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = 32;
        internal const int crypto_box_curve25519xsalsa20poly1305_SEEDBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xsalsa20poly1305_keypair(
            byte[] pk,
            byte[] sk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xsalsa20poly1305_seed_keypair(
            byte[] pk,
            byte[] sk,
            byte[] seed);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_detached(
            byte[] c,
            byte[] mac,
            byte[] m,
            ulong mlen,
            byte[] n,
            byte[] pk,
            byte[] sk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_easy(
            byte[] c,
            byte[] m,
            ulong mlen,
            byte[] n,
            byte[] pk,
            byte[] sk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_open_detached(
            byte[] m,
            byte[] c,
            byte[] mac,
            ulong clen,
            byte[] n,
            byte[] pk,
            byte[] sk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_open_easy(
            byte[] m,
            byte[] c,
            ulong clen,
            byte[] n,
            byte[] pk,
            byte[] sk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_seal(
            byte[] c,
            byte[] m,
            ulong mlen,
            byte[] pk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_seal_open(
            byte[] m,
            byte[] c,
            ulong clen,
            byte[] pk,
            byte[] sk);
    }
}

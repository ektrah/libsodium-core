using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_scryptsalsa208sha256_SALTBYTES = 32;
        internal const int crypto_pwhash_scryptsalsa208sha256_STRBYTES = 102;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256(
            byte[] @out,
            ulong outlen,
            byte[] passwd,
            ulong passwdlen,
            byte[] salt,
            ulong opslimit,
            nuint memlimit);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str(
            byte[] @out,
            byte[] passwd,
            ulong passwdlen,
            ulong opslimit,
            nuint memlimit);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str_verify(
            byte[] str,
            byte[] passwd,
            ulong passwdlen);
    }
}

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_argon2i_ALG_ARGON2I13 = 1;
        internal const int crypto_pwhash_argon2id_ALG_ARGON2ID13 = 2;
        internal const int crypto_pwhash_argon2id_SALTBYTES = 16;
        internal const int crypto_pwhash_argon2id_STRBYTES = 128;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash(
            byte[] @out,
            ulong outlen,
            byte[] passwd,
            ulong passwdlen,
            byte[] salt,
            ulong opslimit,
            nuint memlimit,
            int alg);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str(
            byte[] @out,
            byte[] passwd,
            ulong passwdlen,
            ulong opslimit,
            nuint memlimit);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_needs_rehash(
            byte[] str,
            ulong opslimit,
            nuint memlimit);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_verify(
            byte[] str,
            byte[] passwd,
            ulong passwdlen);
    }
}

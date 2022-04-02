using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int sodium_base64_VARIANT_ORIGINAL = 1;
        internal const int sodium_base64_VARIANT_ORIGINAL_NO_PADDING = 3;
        internal const int sodium_base64_VARIANT_URLSAFE = 5;
        internal const int sodium_base64_VARIANT_URLSAFE_NO_PADDING = 7;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_base642bin(
            byte[] bin,
            nuint bin_maxlen,
            byte[] b64,
            nuint b64_len,
            byte[] ignore,
            ref nuint bin_len,
            IntPtr b64_end,
            int variant);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint sodium_base64_encoded_len(
            nuint bin_len,
            int variant);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_bin2base64(
            IntPtr b64,
            nuint b64_maxlen,
            byte[] bin,
            nuint bin_len,
            int variant);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_compare(
            byte[] b1_,
            byte[] b2_,
            nuint len);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_increment(
            byte[] n,
            nuint nlen);
    }
}

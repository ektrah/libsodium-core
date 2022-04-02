using System;
using System.Runtime.InteropServices;
using System.Text;
using static Interop.Libsodium;

namespace Sodium
{
    public static partial class Utilities
    {
        /// <summary>Represents Base64 encoding variants.</summary>
        public enum Base64Variant
        {
            /// <summary>Original Base64 encoding variant.</summary>
            Original = sodium_base64_VARIANT_ORIGINAL,
            /// <summary>Original Base64 encoding variant with no padding.</summary>
            OriginalNoPadding = sodium_base64_VARIANT_ORIGINAL_NO_PADDING,
            /// <summary>Urlsafe Base64 encoding variant.</summary>
            UrlSafe = sodium_base64_VARIANT_URLSAFE,
            /// <summary>Urlsafe Base64 encoding variant with no padding.</summary>
            UrlSafeNoPadding = sodium_base64_VARIANT_URLSAFE_NO_PADDING,
        }

        /// <summary>Takes byte array and converts it to Base64 encoded string.</summary>
        /// <param name="data">Data to be encoded.</param>
        /// <param name="variant">Base64 encoding variant.</param>
        /// <exception cref="OverflowException"></exception>
        /// <returns>Base64 encoded string.</returns>
        public static string BinaryToBase64(byte[] data, Base64Variant variant = Base64Variant.Original)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Data is null, encoding failed");
            if (data.Length == 0)
                return string.Empty;

            var base64MaxLen = sodium_base64_encoded_len((nuint)data.Length, (int)variant);
            var b64 = Marshal.AllocHGlobal((int)base64MaxLen);
            try
            {
                var base64 = sodium_bin2base64(b64, base64MaxLen, data, (nuint)data.Length, (int)variant);
                if (base64 == IntPtr.Zero)
                {
                    throw new OverflowException("Internal error, encoding failed");
                }

                return Marshal.PtrToStringAnsi(base64);
            }
            finally
            {
                Marshal.FreeHGlobal(b64);
            }
        }

        /// <summary>Converts Base64 encoded string to byte array.</summary>
        /// <param name="base64">Base64 encoded string.</param>
        /// <param name="ignoredChars">Characters which will be ignored in decoding.</param>
        /// <param name="variant">Base64 encoding variant</param>
        /// <exception cref="Exception"></exception>
        /// <returns>A byte array of decoded Base64 string</returns>
        public static byte[] Base64ToBinary(string base64, string? ignoredChars, Base64Variant variant = Base64Variant.Original)
        {
            if (base64 == null)
                throw new ArgumentNullException(nameof(base64), "Data is null, encoding failed");
            if (base64.Length == 0)
                return Array.Empty<byte>();

            var b64 = Encoding.UTF8.GetBytes(base64);
            var ignore = Encoding.UTF8.GetBytes(ignoredChars ?? string.Empty);

            var bin = new byte[base64.Length];
            var binLength = (nuint)0;
            var ret = sodium_base642bin(bin, (nuint)bin.Length, b64, (nuint)b64.Length, ignore, ref binLength, IntPtr.Zero, (int)variant);

            if (ret != 0)
            {
                throw new Exception("Internal error, decoding failed.");
            }

            Array.Resize(ref bin, (int)binLength);
            return bin;
        }
    }
}

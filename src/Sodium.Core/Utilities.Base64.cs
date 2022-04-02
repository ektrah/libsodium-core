using System;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class Utilities
    {
        /// <summary>Represents Base64 encoding variants.</summary>
        public enum Base64Variant
        {
            /// <summary>Original Base64 encoding variant.</summary>
            Original = 1,
            /// <summary>Original Base64 encoding variant with no padding.</summary>
            OriginalNoPadding = 3,
            /// <summary>Urlsafe Base64 encoding variant.</summary>
            UrlSafe = 5,
            /// <summary>Urlsafe Base64 encoding variant with no padding.</summary>
            UrlSafeNoPadding = 7
        }

        /// <summary>Takes byte array and converts it to Base64 encoded string.</summary>
        /// <param name="data">Data to be encoded.</param>
        /// <param name="variant">Base64 encoding variant.</param>
        /// <exception cref="OverflowException"></exception>
        /// <returns>Base64 encoded string.</returns>
        public static string BinaryToBase64(byte[] data, Base64Variant variant = Base64Variant.Original)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "Data is null, encoding failed");
            }

            if (data.Length == 0)
            {
                return string.Empty;
            }

            int base64MaxLen = SodiumLibrary.sodium_base64_encoded_len(data.Length, (int)variant);
            var b64 = new byte[base64MaxLen];
            var base64 = SodiumLibrary.sodium_bin2base64(b64, base64MaxLen, data, data.Length, (int)variant);
            if (base64 == IntPtr.Zero)
            {
                throw new OverflowException("Internal error, encoding failed.");
            }

            return Marshal.PtrToStringAnsi(base64)?.TrimEnd('\0');
        }

        /// <summary>Converts Base64 encoded string to byte array.</summary>
        /// <param name="base64">Base64 encoded string.</param>
        /// <param name="ignoredChars">Characters which will be ignored in decoding.</param>
        /// <param name="variant">Base64 encoding variant</param>
        /// <exception cref="Exception"></exception>
        /// <returns>A byte array of decoded Base64 string</returns>
        public static byte[] Base64ToBinary(string base64, string ignoredChars, Base64Variant variant = Base64Variant.Original)
        {
            if (base64 == null)
            {
                throw new ArgumentNullException(nameof(base64), "Data is null, encoding failed");
            }
            if (base64 == string.Empty)
            {
                return new byte[] { };
            }

            var bin = Marshal.AllocHGlobal(base64.Length);
            var ret = SodiumLibrary.sodium_base642bin(bin, base64.Length, base64, base64.Length, ignoredChars, out var binLength,
              out var lastChar, (int)variant);

            if (ret != 0)
            {
                throw new Exception("Internal error, decoding failed.");
            }

            var decodedArr = new byte[binLength];
            Marshal.Copy(bin, decodedArr, 0, binLength);
            Marshal.FreeHGlobal(bin);

            return decodedArr;
        }
    }
}

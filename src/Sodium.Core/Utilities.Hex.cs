using System;

namespace Sodium
{
    public static partial class Utilities
    {
        /// <summary>Represents HEX formats.</summary>
        public enum HexFormat
        {
            /// <summary>a hex string without seperators.</summary>
            None,
            /// <summary>a hex string with colons (dd:33:dd).</summary>
            Colon,
            /// <summary>a hex string with hyphens (dd-33-dd).</summary>
            Hyphen,
            /// <summary>a hex string with spaces (dd 33 dd).</summary>
            Space
        }

        /// <summary>Represents HEX cases.</summary>
        public enum HexCase
        {
            /// <summary>lower-case hex-encoded.</summary>
            Lower,
            /// <summary>upper-case hex-encoded</summary>
            Upper
        }

        /// <summary>Takes a byte array and returns a hex-encoded string.</summary>
        /// <param name="data">Data to be encoded.</param>
        /// <returns>Hex-encoded string, lodercase.</returns>
        /// <exception cref="OverflowException"></exception>
        public static string BinaryToHex(byte[] data)
        {
            return BinaryToHex(data, HexFormat.None, HexCase.Lower);
        }

        /// <summary>Takes a byte array and returns a hex-encoded string.</summary>
        /// <param name="data">Data to be encoded.</param>
        /// <param name="format">Output format.</param>
        /// <param name="hcase">Lowercase or uppercase.</param>
        /// <returns>Hex-encoded string.</returns>
        /// <remarks>Bit fiddling by CodeInChaos.</remarks>
        /// <remarks>This method don`t use libsodium, but it can be useful for generating human readable fingerprints.</remarks>
        public static string BinaryToHex(byte[] data, HexFormat format, HexCase hcase = HexCase.Lower)
        {
            if (data.Length == 0)
                return string.Empty;

            var hex = new char[data.Length * 3];
            var pos = 0;

            for (var i = 0; i < data.Length; i++)
            {
                var b = data[i] >> 4;
                var c = data[i] & 0xF;

                switch (hcase)
                {
                    case HexCase.Lower:
                        hex[pos++] = (char)(87 + b + (((b - 10) >> 31) & -39));
                        hex[pos++] = (char)(87 + c + (((c - 10) >> 31) & -39));
                        break;
                    default:
                        hex[pos++] = (char)(55 + b + (((b - 10) >> 31) & -7));
                        hex[pos++] = (char)(55 + c + (((c - 10) >> 31) & -7));
                        break;
                }

                switch (format)
                {
                    case HexFormat.Colon:
                        hex[pos++] = ':';
                        break;
                    case HexFormat.Hyphen:
                        hex[pos++] = '-';
                        break;
                    case HexFormat.Space:
                        hex[pos++] = ' ';
                        break;
                    default:
                        //no formatting
                        break;
                }
            }

            switch (format)
            {
                case HexFormat.Colon:
                case HexFormat.Hyphen:
                case HexFormat.Space:
                    pos--;
                    break;
            }

            return new string(hex, 0, pos);
        }

        /// <summary>Converts a hex-encoded string to a byte array.</summary>
        /// <param name="hex">Hex-encoded data.</param>
        /// <returns>A byte array of the decoded string.</returns>
        /// <exception cref="Exception"></exception>
        public static byte[] HexToBinary(string hex)
        {
            const string IGNORED_CHARS = ":- ";

            var bin = new byte[hex.Length >> 1];
            int bin_pos = 0;
            uint c_acc = 0;
            int state = 0;

            for (var hex_pos = 0; hex_pos < hex.Length; hex_pos++)
            {
                var c = hex[hex_pos];
                var c_num = c ^ 48U;
                var c_num0 = (c_num - 10U) >> 8;
                var c_alpha = (c & ~32U) - 55U;
                var c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;

                if ((c_num0 | c_alpha0) == 0U)
                {
                    if (state == 0 && IGNORED_CHARS.Contains(c))
                    {
                        continue;
                    }
                    throw new Exception("Decoding failed");
                }

                var c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);

                if (state == 0)
                {
                    c_acc = c_val << 4;
                }
                else
                {
                    bin[bin_pos++] = (byte)(c_acc | c_val);
                }

                state = ~state;
            }

            if (state != 0)
            {
                throw new Exception("Decoding failed");
            }

            Array.Resize(ref bin, bin_pos);
            return bin;
        }
    }
}

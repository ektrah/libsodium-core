using System;
using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace Sodium
{
    /// <summary>
    /// libsodium core information.
    /// </summary>
    public static partial class SodiumCore
    {
        /// <summary>Gets random bytes</summary>
        /// <param name="count">The count of bytes to return.</param>
        /// <returns>An array of random bytes.</returns>
        public static byte[] GetRandomBytes(int count)
        {
            var buffer = new byte[count];

            SodiumCore.Initialize();
            randombytes_buf(buffer, (nuint)buffer.Length);

            return buffer;
        }

        /// <summary>
        /// Gets a random number.
        /// </summary>
        /// <param name="upperBound">Integer between 0 and 2147483647.</param>
        /// <returns>An unpredictable value between 0 and upperBound (excluded).</returns>
        public static int GetRandomNumber(int upperBound)
        {
            if (upperBound < 0)
                throw new ArgumentOutOfRangeException(nameof(upperBound), "upperBound cannot be negative");

            SodiumCore.Initialize();
            var randomNumber = randombytes_uniform((uint)upperBound);

            return (int)randomNumber;
        }

        /// <summary>
        /// Returns the version of libsodium in use.
        /// </summary>
        /// <returns>
        /// The sodium version string.
        /// </returns>
        public static string? SodiumVersionString()
        {
            return Marshal.PtrToStringAnsi(sodium_version_string());
        }

        /// <summary>Initialize libsodium.</summary>
        /// <remarks>This only needs to be done once, so this prevents repeated calls.</remarks>
        public static void Init()
        {
            SodiumCore.Initialize();
        }
    }
}

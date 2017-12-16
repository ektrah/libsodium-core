using System;
using System.Runtime.InteropServices;
namespace Sodium
{
    /// <summary>
    /// libsodium core information.
    /// </summary>
    public static class SodiumCore
    {
        private static bool _isInit;

        static SodiumCore()
        {
            Init();
        }

        /// <summary>Gets random bytes</summary>
        /// <param name="count">The count of bytes to return.</param>
        /// <returns>An array of random bytes.</returns>
        public static byte[] GetRandomBytes(int count) => ByteBuffer.Use(count, buffer => SodiumLibrary.randombytes_buf(buffer, count));

        /// <summary>
        /// Gets a random number.
        /// </summary>
        /// <param name="upperBound">Integer between 0 and 2147483647.</param>
        /// <returns>An unpredictable value between 0 and upperBound (excluded).</returns>
        public static int GetRandomNumber(int upperBound) => SodiumLibrary.randombytes_uniform(upperBound);

        /// <summary>
        /// Returns the version of libsodium in use.
        /// </summary>
        /// <returns>
        /// The sodium version string.
        /// </returns>
        public static string SodiumVersionString() => Marshal.PtrToStringAnsi(SodiumLibrary.sodium_version_string());

        /// <summary>Initialize libsodium.</summary>
        /// <remarks>This only needs to be done once, so this prevents repeated calls.</remarks>
        public static void Init()
        {
            if (!_isInit)
            {
                SodiumLibrary.sodium_init();
                _isInit = true;
            }
        }
    }
}

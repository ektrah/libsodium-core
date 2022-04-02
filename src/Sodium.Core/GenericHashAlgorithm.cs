using System;
using System.Security.Cryptography;
using System.Text;
using Sodium.Exceptions;
using static Interop.Libsodium;

namespace Sodium
{
    public static partial class GenericHash
    {
        /// <summary>
        /// Blake2b implementation of HashAlgorithm suitable for hashing streams.
        /// </summary>
        public class GenericHashAlgorithm : HashAlgorithm
        {
            private crypto_generichash_blake2b_state hashState;
            private readonly byte[] key;
            private readonly int bytes;

            /// <summary>
            /// Initializes the hashing algorithm.
            /// </summary>
            /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
            /// <param name="bytes">The size (in bytes) of the desired result.</param>
            /// <exception cref="KeyOutOfRangeException"></exception>
            /// <exception cref="BytesOutOfRangeException"></exception>
            public GenericHashAlgorithm(string? key, int bytes) : this(key != null ? Encoding.UTF8.GetBytes(key) : null, bytes) { }

            /// <summary>
            /// Initializes the hashing algorithm.
            /// </summary>
            /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
            /// <param name="bytes">The size (in bytes) of the desired result.</param>
            /// <exception cref="KeyOutOfRangeException"></exception>
            /// <exception cref="BytesOutOfRangeException"></exception>
            public GenericHashAlgorithm(byte[]? key, int bytes)
            {
                //validate the length of the key
                if (key != null)
                {
                    if (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN)
                    {
                        throw new KeyOutOfRangeException(string.Format("key must be between {0} and {1} bytes in length.",
                          KEY_BYTES_MIN, KEY_BYTES_MAX));
                    }
                }
                else
                {
                    key = Array.Empty<byte>();
                }

                this.key = key;

                //validate output length
                if (bytes > BYTES_MAX || bytes < BYTES_MIN)
                    throw new BytesOutOfRangeException("bytes", bytes,
                      string.Format("bytes must be between {0} and {1} bytes in length.", BYTES_MIN, BYTES_MAX));

                this.bytes = bytes;

                Initialize();
            }

            override public void Initialize()
            {
                crypto_generichash_blake2b_init(ref hashState, key, (nuint)key.Length, (nuint)bytes);
            }

            override protected void HashCore(byte[] array, int ibStart, int cbSize)
            {
                byte[] subArray = new byte[cbSize];
                Array.Copy(array, ibStart, subArray, 0, cbSize);
                crypto_generichash_blake2b_update(ref hashState, subArray, (ulong)cbSize);
            }

            override protected byte[] HashFinal()
            {
                byte[] buffer = new byte[bytes];
                crypto_generichash_blake2b_final(ref hashState, buffer, (nuint)bytes);
                return buffer;
            }
        }
    }
}

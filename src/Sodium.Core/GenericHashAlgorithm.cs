using Sodium.Exceptions;
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;

namespace Sodium
{
    public partial class GenericHash
    {
        /// <summary>
        /// Blake2b implementation of HashAlgorithm suitable for hashing streams.
        /// </summary>
        public class GenericHashAlgorithm : HashAlgorithm
        {
            private readonly IntPtr _hashStatePtr;
            private readonly byte[] _key;
            private readonly int _bytes;

            /// <summary>
            /// Initializes the hashing algorithm.
            /// </summary>
            /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
            /// <param name="bytes">The size (in bytes) of the desired result.</param>
            /// <exception cref="KeyOutOfRangeException"></exception>
            /// <exception cref="BytesOutOfRangeException"></exception>
            public GenericHashAlgorithm(string key, int bytes)
                : this(Encoding.UTF8.GetBytes(key), bytes) { }

            /// <summary>
            /// Initializes the hashing algorithm.
            /// </summary>
            /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
            /// <param name="bytes">The size (in bytes) of the desired result.</param>
            /// <exception cref="KeyOutOfRangeException"></exception>
            /// <exception cref="BytesOutOfRangeException"></exception>
            public GenericHashAlgorithm(byte[] key, int bytes)
            {
                _hashStatePtr = Marshal.AllocHGlobal(Marshal.SizeOf<SodiumLibrary.HashState>());

                //validate the length of the key
                int keyLength;
                if (key != null)
                {
                    if (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN)
                        throw new KeyOutOfRangeException($"key must be between {KEY_BYTES_MIN} and {KEY_BYTES_MAX} bytes in length.");

                    keyLength = key.Length;
                }
                else
                {
                    key = new byte[0];
                    keyLength = 0;
                }

                _key = key;

                //validate output length
                if (bytes > BYTES_MAX || bytes < BYTES_MIN)
                    throw new BytesOutOfRangeException(nameof(bytes), bytes, $"bytes must be between {BYTES_MIN} and {BYTES_MAX} bytes in length.");

                _bytes = bytes;

                Initialize();
            }

            ~GenericHashAlgorithm()
            {
                Marshal.FreeHGlobal(_hashStatePtr);
            }

            public override void Initialize()
            {
                SodiumLibrary.crypto_generichash_init(_hashStatePtr, _key, _key.Length, _bytes);
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                ByteBuffer.Slice(array, ibStart, cbSize, buffer =>
                     SodiumLibrary.crypto_generichash_update(_hashStatePtr, buffer, cbSize));
            }

            protected override byte[] HashFinal()
            {
                return ByteBuffer.Use(_bytes, buffer =>
                    SodiumLibrary.crypto_generichash_final(_hashStatePtr, buffer, _bytes));
            }
        }
    }
}

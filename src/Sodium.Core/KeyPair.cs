using System;
using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>A public / private key pair.</summary>
    public class KeyPair : IDisposable
    {
        private readonly byte[] _privateKey;

        /// <summary>Gets or sets the Public Key.</summary>
        public byte[] PublicKey { get; }

        /// <summary>Gets or sets the Private Key.</summary>
        public byte[] PrivateKey
        {
            get
            {
                UnprotectKey();
                var tmp = new byte[_privateKey.Length];
                Array.Copy(_privateKey, tmp, tmp.Length);
                ProtectKey();

                return tmp;
            }
        }

        /// <summary>Initializes a new instance of the <see cref="KeyPair"/> class.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public KeyPair(byte[] publicKey, byte[] privateKey)
        {
            //verify that the private key length is a multiple of 16
            if (privateKey.Length % 16 != 0)
                throw new KeyOutOfRangeException("Private Key length must be a multiple of 16 bytes.");

            PublicKey = publicKey;
            _privateKey = privateKey;

            ProtectKey();
        }

        ~KeyPair()
        {
            Dispose();
        }

        /// <summary>Dispose of private key in memory.</summary>
        public void Dispose()
        {
            if (_privateKey != null && _privateKey.Length > 0)
                Array.Clear(_privateKey, 0, _privateKey.Length);
        }

        private void ProtectKey()
        {
#if NET461
            ProtectedMemory.Protect(_privateKey, MemoryProtectionScope.SameProcess);
#endif
        }

        private void UnprotectKey()
        {
#if NET461
            ProtectedMemory.Unprotect(_privateKey, MemoryProtectionScope.SameProcess);
#endif
        }
    }
}

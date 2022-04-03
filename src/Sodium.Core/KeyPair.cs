using System;
using Sodium.Exceptions;

namespace Sodium
{
    /// <summary>A public / private key pair.</summary>
    public class KeyPair : IDisposable
    {
        private readonly byte[] _publicKey;
        private readonly byte[] _privateKey;

        /// <summary>Initializes a new instance of the <see cref="KeyPair"/> class.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public KeyPair(byte[] publicKey, byte[] privateKey)
        {
            _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        }

        /// <summary>Gets the Public Key.</summary>
        public byte[] PublicKey => (byte[])_publicKey.Clone();

        /// <summary>Gets the Private Key.</summary>
        public byte[] PrivateKey => (byte[])_privateKey.Clone();

        /// <summary>Dispose of private key in memory.</summary>
        public void Dispose()
        {
            // clearing managed byte arrays has no practical result, so this method is now a no-op
        }
    }
}

using System;

namespace Sodium
{
    /// <summary>A ciphertext / mac pair.</summary>
    public class DetachedBox
    {
        private readonly byte[] _cipherText;
        private readonly byte[] _mac;

        /// <summary>Initializes a new instance of the <see cref="DetachedBox"/> class.</summary>
        [Obsolete("Use DetachedBox(byte[], byte[]) instead", error: true)]
        public DetachedBox()
        {
            throw new NotSupportedException();
        }

        /// <summary>Initializes a new instance of the <see cref="DetachedBox"/> class.</summary>
        /// <param name="cipherText">The cipher.</param>
        /// <param name="mac">The 16 byte mac.</param>
        public DetachedBox(byte[] cipherText, byte[] mac)
        {
            _cipherText = cipherText ?? throw new ArgumentNullException(nameof(cipherText));
            _mac = mac ?? throw new ArgumentNullException(nameof(mac));
        }

        /// <summary>Gets or sets the Cipher.</summary>
        public byte[] CipherText
        {
            get => (byte[])_cipherText.Clone();

            [Obsolete("Create a new instance of DetachedBox instead", error: true)]
            set => throw new NotSupportedException();
        }

        /// <summary>Gets or sets the MAC.</summary>
        public byte[] Mac
        {
            get => (byte[])_mac.Clone();

            [Obsolete("Create a new instance of DetachedBox instead", error: true)]
            set => throw new NotSupportedException();
        }
    }
}

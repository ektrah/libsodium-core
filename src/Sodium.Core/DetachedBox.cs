using System;

namespace Sodium
{
    /// <summary>A ciphertext / mac pair.</summary>
    public class DetachedBox
    {
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
            CipherText = cipherText ?? throw new ArgumentNullException(nameof(cipherText));
            Mac = mac ?? throw new ArgumentNullException(nameof(mac));
        }

        /// <summary>Gets or sets the Cipher.</summary>
        public byte[] CipherText { get; set; }

        /// <summary>Gets or sets the MAC.</summary>
        public byte[] Mac { get; set; }
    }
}

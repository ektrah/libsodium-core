using System;

namespace Sodium
{
    [Obsolete("Use SecretAeadChaCha20Poly1305 instead")]
    public static class SecretAead
    {
        [Obsolete("Use SecretAeadChaCha20Poly1305.GenerateNonce instead")]
        public static byte[] GenerateNonce() => SecretAeadChaCha20Poly1305.GenerateNonce();

        [Obsolete("Use SecretAeadChaCha20Poly1305.Encrypt instead")]
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key, byte[]? additionalData = null) => SecretAeadChaCha20Poly1305.Encrypt(message, nonce, key, additionalData);

        [Obsolete("Use SecretAeadChaCha20Poly1305.Decrypt instead")]
        public static byte[] Decrypt(byte[] cipher, byte[] nonce, byte[] key, byte[]? additionalData = null) => SecretAeadChaCha20Poly1305.Decrypt(cipher, nonce, key, additionalData);
    }
}

using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  /// <summary>Provides hashing via selected primitive.</summary>
  public class CryptoHash
  {
    //pulled from various #define statements; may break with new versions
    private const int SHA512_BYTES = 64;
    private const int SHA256_BYTES = 32;

    /// <summary>Hashes a string using the default algorithm (This is what you want to use)</summary>
    /// <param name="message">The message.</param>
    /// <returns>Hex-encoded hash.</returns>
    public static byte[] Hash(string message)
    {
      return Hash(Encoding.UTF8.GetBytes(message));
    }

    /// <summary>Hashes a byte array using the default algorithm (This is what you want to use)</summary>
    /// <param name="message">The message.</param>
    /// <returns></returns>
    public static byte[] Hash(byte[] message)
    {
      var buffer = new byte[SHA512_BYTES];

      var hash = DynamicInvoke.GetDynamicInvoke<_CryptoHash>("crypto_hash", SodiumCore.LibraryName());
      hash(buffer, message, message.Length);

      return buffer;
    }

    /// <summary>Hashes a string using the SHA512 algorithm</summary>
    /// <param name="message">The message.</param>
    /// <returns>Hex-encoded hash.</returns>
    public static byte[] Sha512(string message)
    {
      return Sha512(Encoding.UTF8.GetBytes(message));
    }

    /// <summary>Hashes a byte array using the SHA512 algorithm</summary>
    /// <param name="message">The message.</param>
    /// <returns></returns>
    public static byte[] Sha512(byte[] message)
    {
      var buffer = new byte[SHA512_BYTES];

      var hash = DynamicInvoke.GetDynamicInvoke<_Sha512>("crypto_hash_sha512", SodiumCore.LibraryName());
      hash(buffer, message, message.Length);

      return buffer;
    }

    /// <summary>Hashes a string using the SHA256 algorithm</summary>
    /// <param name="message">The message.</param>
    /// <returns>Hex-encoded hash.</returns>
    public static byte[] Sha256(string message)
    {
      return Sha256(Encoding.UTF8.GetBytes(message));
    }

    /// <summary>Hashes a byte array using the SHA256 algorithm</summary>
    /// <param name="message">The message.</param>
    /// <returns></returns>
    public static byte[] Sha256(byte[] message)
    {
      var buffer = new byte[SHA256_BYTES];

      var hash = DynamicInvoke.GetDynamicInvoke<_Sha256>("crypto_hash_sha256", SodiumCore.LibraryName());
      hash(buffer, message, message.Length);

      return buffer;
    }

    //crypto_hash
    private delegate int _CryptoHash(byte[] buffer, byte[] message, long length);
    //crypto_hash_sha512
    private delegate int _Sha512(byte[] buffer, byte[] message, long length);
    //crypto_hash_sha256
    private delegate int _Sha256(byte[] buffer, byte[] message, long length);
  }
}

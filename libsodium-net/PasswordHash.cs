using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  public class PasswordHash
  {
    private const uint SCRYPT_SALSA208_SHA256_BYTES = 102U;
    private const uint SCRYPT_SALSA208_SHA256_SALTBYTES = 32U;

    private const long OPSLIMIT_INTERACTIVE = 524288;
    private const long OPSLIMIT_MODERATE = 8388608;
    private const long OPSLIMIT_SENSITIVE = 33554432;
    private const int MEMLIMIT_INTERACTIVE = 16777216;
    private const int MEMLIMIT_MODERATE = 100000000;
    private const int MEMLIMIT_SENSITIVE = 1073741824;

    /// <summary>
    /// Returns the hash in a string format, which includes the generated salt.
    /// </summary>
    /// <param name="password">The password.</param>
    /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
    /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
    /// <returns>Returns an zero-terminated ASCII encoded string of the computed password and hash.</returns>
    public static string HashSalsa208Sha256String(string password, long opsLimit, int memLimit)
    {
      if (password == null)
        throw new ArgumentNullException("Password cannot be null");

      if (opsLimit <= 0 || memLimit <= 0)
        throw new ArgumentOutOfRangeException("opsLimit or memLimit cannot be zero or negative");

      var buffer = new byte[SCRYPT_SALSA208_SHA256_BYTES];
      var pass = Encoding.UTF8.GetBytes(password);

      int ret;

      if (SodiumCore.Is64)
      {
        ret = _SCRYPTX_SALSA208_SHA256_STR_X64(buffer, pass, pass.LongLength, opsLimit, memLimit);
      }
      else
      {
        ret = _SCRYPTX_SALSA208_SHA256_STR_X86(buffer, pass, pass.LongLength, opsLimit, memLimit);
      }

      if (ret != 0)
      {
          throw new OutOfMemoryException("Internal error, hash failed");
      }

      return Encoding.UTF8.GetString(buffer);
    }

    /// <summary>
    /// Returns the hash in a string format, which includes the generated salt.
    /// </summary>
    /// <param name="password">The password.</param>
    /// <param name="limit">The limit for computation.</param>
    /// <returns>Returns an zero-terminated ASCII encoded string of the computed password and hash.</returns>
    public static string HashSalsa208Sha256String(string password, HashSalsa208Sha256Limit limit = HashSalsa208Sha256Limit.Interactive)
    {
        if (password == null)
            throw new ArgumentNullException("Password cannot be null");

        var buffer = new byte[SCRYPT_SALSA208_SHA256_BYTES];
        var pass = Encoding.UTF8.GetBytes(password);

        int ret, memLimit;
        long opsLimit;
        switch (limit)
        {
            case HashSalsa208Sha256Limit.Interactive:
                opsLimit = OPSLIMIT_INTERACTIVE;
                memLimit = MEMLIMIT_INTERACTIVE;
                break;
            case HashSalsa208Sha256Limit.Moderate:
                opsLimit = OPSLIMIT_MODERATE;
                memLimit = MEMLIMIT_MODERATE;
                break; 
            case HashSalsa208Sha256Limit.Sensitive:
                opsLimit = OPSLIMIT_SENSITIVE;
                memLimit = MEMLIMIT_SENSITIVE;
                break;
            default:
                opsLimit = OPSLIMIT_INTERACTIVE;
                memLimit = MEMLIMIT_INTERACTIVE;
                break;
        }

        if (SodiumCore.Is64)
        {
            ret = _SCRYPTX_SALSA208_SHA256_STR_X64(buffer, pass, pass.LongLength, opsLimit, memLimit);
        }
        else
        {
            ret = _SCRYPTX_SALSA208_SHA256_STR_X86(buffer, pass, pass.LongLength, opsLimit, memLimit);
        }

        if (ret != 0)
        {
            throw new OutOfMemoryException("Internal error, hash failed");
        }

        return Encoding.UTF8.GetString(buffer);
    }

    /// <summary>
    /// Derives a secret key of any size from a password and a salt.
    /// </summary>
    /// <param name="password">The password.</param>
    /// <param name="salt">The salt.</param>
    /// <param name="opsLimit">Represents a maximum amount of computations to perform.</param>
    /// <param name="memLimit">Is the maximum amount of RAM that the function will use, in bytes.</param>
    /// <param name="outputLength">The length of the computed output array.</param>
    /// <returns>Returns a byte array of the given size.</returns>
    public static byte[] HashSalsa208Sha256(string password, string salt, long opsLimit, int memLimit, long outputLength = SCRYPT_SALSA208_SHA256_SALTBYTES)
    {
        if (password == null)
            throw new ArgumentNullException("Password cannot be null");
        if (salt == null)
            throw new ArgumentNullException("Salt cannot be null");
        if (opsLimit <= 0 || memLimit <= 0)
            throw new ArgumentOutOfRangeException("opsLimit or memLimit cannot be zero or negative");
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException("OutputLength cannot be zero or negative");

        var buffer = new byte[outputLength];
        var pass = Encoding.UTF8.GetBytes(password);
        var saltAsBytes = Encoding.UTF8.GetBytes(salt);

        int ret;

        if (SodiumCore.Is64)
        {
            ret = _SCRYPTX_SALSA208_SHA256_X64(buffer, buffer.Length, pass, pass.LongLength, saltAsBytes, opsLimit, memLimit);
        }
        else
        {
            ret = _SCRYPTX_SALSA208_SHA256_X86(buffer, buffer.Length, pass, pass.LongLength, saltAsBytes, opsLimit, memLimit);
        }

        if (ret != 0)
        {
            throw new OutOfMemoryException("Internal error, hash failed");
        }

        return buffer;
    }

    /// <summary>
    /// Derives a secret key of any size from a password and a salt.
    /// </summary>
    /// <param name="password">The password.</param>
    /// <param name="salt">The salt.</param>
    /// <param name="limit">The limit for computation.</param>
    /// <param name="outputLength">The length of the computed output array.</param>
    /// <returns>Returns a byte array of the given size.</returns>
    public static byte[] HashSalsa208Sha256(string password, string salt, HashSalsa208Sha256Limit limit = HashSalsa208Sha256Limit.Interactive, long outputLength = SCRYPT_SALSA208_SHA256_SALTBYTES)
    {
        if (password == null)
            throw new ArgumentNullException("Password cannot be null");
        if (salt == null)
            throw new ArgumentNullException("Salt cannot be null");
        if (outputLength < 1)
            throw new ArgumentOutOfRangeException("OutputLength must be greater 0");

        var buffer = new byte[outputLength];
        var pass = Encoding.UTF8.GetBytes(password);
        var saltAsBytes = Encoding.UTF8.GetBytes(salt);

        int ret, memLimit;
        long opsLimit;
        switch (limit)
        {
            case HashSalsa208Sha256Limit.Interactive:
                opsLimit = OPSLIMIT_INTERACTIVE;
                memLimit = MEMLIMIT_INTERACTIVE;
                break;
            case HashSalsa208Sha256Limit.Moderate:
                opsLimit = OPSLIMIT_MODERATE;
                memLimit = MEMLIMIT_MODERATE;
                break;
            case HashSalsa208Sha256Limit.Sensitive:
                opsLimit = OPSLIMIT_SENSITIVE;
                memLimit = MEMLIMIT_SENSITIVE;
                break;
            default:
                opsLimit = OPSLIMIT_INTERACTIVE;
                memLimit = MEMLIMIT_INTERACTIVE;
                break;
        }

        if (SodiumCore.Is64)
        {
            ret = _SCRYPTX_SALSA208_SHA256_X64(buffer, buffer.Length, pass, pass.LongLength, saltAsBytes, opsLimit, memLimit);
        }
        else
        {
            ret = _SCRYPTX_SALSA208_SHA256_X86(buffer, buffer.Length, pass, pass.LongLength, saltAsBytes, opsLimit, memLimit);
        }

        if (ret != 0)
        {
            throw new OutOfMemoryException("Internal error, hash failed");
        }

        return buffer;
    }

    /// <summary>
    /// Verifies that a hash generated with HashSalsa208Sha256String matches the supplied password.
    /// </summary>
    /// <param name="hash">The hash.</param>
    /// <param name="password">The password.</param>
    /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
    public static bool HashSalsa208Sha256StringVerify(string hash, string password)
    {
        return HashSalsa208Sha256StringVerify(Encoding.UTF8.GetBytes(hash), Encoding.UTF8.GetBytes(password));
    }

    /// <summary>
    /// Verifies that a hash generated with HashSalsa208Sha256String matches the supplied password.
    /// </summary>
    /// <param name="hash">The hash.</param>
    /// <param name="password">The password.</param>
    /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
    public static bool HashSalsa208Sha256StringVerify(byte[] hash, byte[] password)
    {
      if (hash == null || password == null)
      {
        throw new ArgumentNullException("hash or password cannot be null");
      }

      int ret;

      if (SodiumCore.Is64)
      {
        ret = _SCRYPTX_SALSA208_SHA256_VERIFY_X64(hash, password, password.LongLength);
      }
      else
      {
        ret = _SCRYPTX_SALSA208_SHA256_VERIFY_X86(hash, password, password.LongLength);
      }

      return ret == 0;
    }

    //crypto_pwhash_scryptsalsa208sha256_str
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_pwhash_scryptsalsa208sha256_str", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SCRYPTX_SALSA208_SHA256_STR_X64(byte[] buffer, byte[] password, long passwordLen, long opsLimit, int memLimit);

    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_pwhash_scryptsalsa208sha256_str", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SCRYPTX_SALSA208_SHA256_STR_X86(byte[] buffer, byte[] password, long passwordLen, long opsLimit, int memLimit);

    //crypto_pwhash_scryptsalsa208sha256
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_pwhash_scryptsalsa208sha256", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SCRYPTX_SALSA208_SHA256_X64(byte[] buffer, long bufferLen, byte[] password, long passwordLen, byte[] salt, long opsLimit, int memLimit);
    //
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_pwhash_scryptsalsa208sha256", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SCRYPTX_SALSA208_SHA256_X86(byte[] buffer, long bufferLen, byte[] password, long passwordLen, byte[] salt, long opsLimit, int memLimit);
      
    //crypto_pwhash_scryptsalsa208sha256_str_verify
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_pwhash_scryptsalsa208sha256_str_verify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SCRYPTX_SALSA208_SHA256_VERIFY_X86(byte[] buffer, byte[] password, long passLength);

    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_pwhash_scryptsalsa208sha256_str_verify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SCRYPTX_SALSA208_SHA256_VERIFY_X64(byte[] buffer, byte[] password, long passLength);
  }

  /// <summary>
  /// Represents predefined and useful limits for HashSalsa208Sha256() and HashSalsa208Sha256String().
  /// </summary>
  public enum HashSalsa208Sha256Limit
  {
      /// <summary>For interactive sessions (fast: uses 16MB of RAM).</summary>
      Interactive,
      /// <summary>For normal use (moderate: uses 100MB of RAM).</summary>
      Moderate,
      /// <summary>For highly sensitive data (slow: uses more than 1GB of RAM).</summary>
      Sensitive
  }
}

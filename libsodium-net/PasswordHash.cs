using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  public class PasswordHash
  {
    private const uint SCRYPT_SALSA208_SHA256_BYTES = 102U;

    public static string HashSalsa208Sha256(string password, long opsLimit, int memLimit)
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
        throw new Exception("Internal error, hash failed");
      }

      return Encoding.UTF8.GetString(buffer);
    }

    public static bool HashSalsa208Sha256Verify(string hash, string password)
    {
      return HashSalsa208Sha256Verify(Encoding.UTF8.GetBytes(hash), Encoding.UTF8.GetBytes(password));
    }

    public static bool HashSalsa208Sha256Verify(byte[] hash, byte[] password)
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

    //crypto_pwhash_scryptxsalsa208sha256_str
    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_pwhash_scryptxsalsa208sha256_str", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SCRYPTX_SALSA208_SHA256_STR_X64(byte[] buffer, byte[] password, long passwordLen, long opsLimit, int memLimit);

    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_pwhash_scryptxsalsa208sha256_str", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SCRYPTX_SALSA208_SHA256_STR_X86(byte[] buffer, byte[] password, long passwordLen, long opsLimit, int memLimit);

    //crypto_pwhash_scryptxsalsa208sha256 - unused
    //[DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_pwhash_scryptxsalsa208sha256", CallingConvention = CallingConvention.Cdecl)]
    //private static extern int _SCRYPTX_SALSA208_SHA256_X64(byte[] buffer, long bufferLen, byte[] password, long passwordLen, byte[] salt, long opsLimit, int memLimit);
    //
    //[DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_pwhash_scryptxsalsa208sha256", CallingConvention = CallingConvention.Cdecl)]
    //private static extern int _SCRYPTX_SALSA208_SHA256_X86(byte[] buffer, long bufferLen, byte[] password, long passwordLen, byte[] salt, long opsLimit, int memLimit);

    //crypto_pwhash_scryptxsalsa208sha256_str_verify
    [DllImport(SodiumCore.LIBRARY_X86, EntryPoint = "crypto_pwhash_scryptxsalsa208sha256_str_verify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SCRYPTX_SALSA208_SHA256_VERIFY_X86(byte[] buffer, byte[] password, long passLength);

    [DllImport(SodiumCore.LIBRARY_X64, EntryPoint = "crypto_pwhash_scryptxsalsa208sha256_str_verify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int _SCRYPTX_SALSA208_SHA256_VERIFY_X64(byte[] buffer, byte[] password, long passLength);
  }
}

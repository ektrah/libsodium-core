using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace Sodium
{
  /// <summary>
  /// libsodium library binding.
  /// </summary>
  public static partial class SodiumLibrary
  {
    //randombytes_buf
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe void randombytes_buf(void* buffer, int size);

    //sodium_bin2hex
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe IntPtr sodium_bin2hex(byte* hex, int hexMaxlen, byte* bin, int binLen);
  }

  public static partial class SodiumCore
  {
    /// <summary>Fills existing memory w/ random bytes</summary>
    /// <param name="data">The memory to write to.</param>
    public static void GetRandomBytes(Span<byte> data)
    {
      GetRandomBytes(data, data.Length);
    }

    /// <summary>Fills existing memory w/ random bytes</summary>
    /// <param name="data">The memory to write to.</param>
    /// <param name="count">The count of bytes to write.</param>
    public static void GetRandomBytes(Span<byte> data, int count)
    {
      unsafe
      {
        fixed (byte* ptr = data)
        {
          SodiumLibrary.randombytes_buf(ptr, count);
        }
      }
    }
  }

  public static partial class Utilities
  {
    private static readonly ArrayPool<byte> pool = ArrayPool<byte>.Create();

    /// <summary>Takes a byte array and returns a hex-encoded string.</summary>
    /// <param name="data">The memory to read from.</param>
    /// <returns>Hex-encoded string, lowercase.</returns>
    /// <exception cref="OverflowException"></exception>
    public static string BinaryToHex(ReadOnlySpan<byte> data)
    {
      var target = pool.Rent(data.Length * 2 + 1);
      try
      {
        return BinaryToHex(data, target);
      }
      finally
      {
        pool.Return(target);
      }
    }

    private static string BinaryToHex(ReadOnlySpan<byte> data, Span<byte> target)
    {
      var ret = BinaryToHexImpl(data, target);

      return Marshal.PtrToStringAnsi(ret);
    }

    private static IntPtr BinaryToHexImpl(ReadOnlySpan<byte> data, Span<byte> target)
    {
      unsafe
      {
        fixed (byte* bin = data)
        {
          fixed (byte* str = target)
          {
            var ret = SodiumLibrary.sodium_bin2hex(str, target.Length, bin, data.Length);

            if (ret == IntPtr.Zero)
            {
              throw new OverflowException("Internal error, encoding failed.");
            }

            return ret;
          }
        }
      }
    }
  }
}

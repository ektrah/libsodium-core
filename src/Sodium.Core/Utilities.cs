using Microsoft.Extensions.ObjectPool;
using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;

namespace Sodium
{
  /// <summary>Various utility methods.</summary>
  public static class Utilities
  { 
    /// <summary>Represents HEX formats.</summary>
    public enum HexFormat
    {
      /// <summary>a hex string without separators.</summary>
      None,
      /// <summary>a hex string with colons (dd:33:dd).</summary>
      Colon,
      /// <summary>a hex string with hyphens (dd-33-dd).</summary>
      Hyphen,
      /// <summary>a hex string with spaces (dd 33 dd).</summary>
      Space
    }

    /// <summary>Represents HEX cases.</summary>
    public enum HexCase
    {
      /// <summary>lower-case hex-encoded.</summary>
      Lower,
      /// <summary>upper-case hex-encoded</summary>
      Upper
    }
    
    /// <summary>Takes a byte array and returns a hex-encoded string.</summary>
    /// <param name="data">Data to be encoded.</param>
    /// <returns>Hex-encoded string, lowercase.</returns>
    /// <exception cref="OverflowException"></exception>
    public static string BinaryToHex(byte[] data)
    {
      return BinaryToHex(data.AsSpan(), new byte[data.Length * 2 + 1]);
    }

    internal static ObjectPool<StringBuilder> StringBuilderPool = new DefaultObjectPool<StringBuilder>(new StringBuilderPooledObjectPolicy());

    /// <summary>Takes a byte array and returns a hex-encoded string.</summary>
    /// <param name="data">Data to be encoded.</param>
    /// <param name="format">Output format.</param>
    /// <param name="hcase">Lowercase or uppercase.</param>
    /// <returns>Hex-encoded string.</returns>
    /// <remarks>Bit fiddling by CodeInChaos.</remarks>
    /// <remarks>This method doesn't use libsodium, but it can be useful for generating human readable fingerprints.</remarks>
    public static string BinaryToHex(byte[] data, HexFormat format, HexCase hcase = HexCase.Lower)
    {
      var sb = StringBuilderPool.Get();

      try
      {
        for (var i = 0; i < data.Length; i++)
        {
          if ((i != 0) && (format != HexFormat.None))
          {
            switch (format)
            {
              case HexFormat.Colon:
                sb.Append((char)58);
                break;
              case HexFormat.Hyphen:
                sb.Append((char)45);
                break;
              case HexFormat.Space:
                sb.Append((char)32);
                break;
              default:
                //no formatting
                break;
            }
          }

          var byteValue = data[i] >> 4;

          if (hcase == HexCase.Lower)
          {
            sb.Append((char)(87 + byteValue + (((byteValue - 10) >> 31) & -39))); //lower
          }
          else
          {
            sb.Append((char)(55 + byteValue + (((byteValue - 10) >> 31) & -7))); //upper 
          }
          byteValue = data[i] & 0xF;

          if (hcase == HexCase.Lower)
          {
            sb.Append((char)(87 + byteValue + (((byteValue - 10) >> 31) & -39))); //lower
          }
          else
          {
            sb.Append((char)(55 + byteValue + (((byteValue - 10) >> 31) & -7))); //upper 
          }
        }

        return sb.ToString();
      }
      finally
      {
        StringBuilderPool.Return(sb);
      }
    }

    internal static readonly ArrayPool<byte> Pool = ArrayPool<byte>.Create();

    /// <summary>Takes a byte array and returns a hex-encoded string.</summary>
    /// <param name="data">The memory to read from.</param>
    /// <returns>Hex-encoded string, lowercase.</returns>
    /// <exception cref="OverflowException"></exception>
    public static string BinaryToHex(ReadOnlySpan<byte> data)
    {
      var target = Pool.Rent(data.Length * 2 + 1);
      try
      {
        return BinaryToHex(data, target);
      }
      finally
      {
        Pool.Return(target);
      }
    }

    public static string BinaryToHex(ReadOnlySpan<byte> data, Span<byte> target)
    {
      return Marshal.PtrToStringAnsi(BinaryToHexImpl(data, target));
    }

    private static IntPtr BinaryToHexImpl(ReadOnlySpan<byte> data, Span<byte> target)
    {
      unsafe
      {
        fixed (byte* bin = &data.GetPinnableReference())
        {
          fixed (byte* str = &target.GetPinnableReference())
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

    /// <summary>Converts a hex-encoded string to a byte array.</summary>
    /// <param name="hex">Hex-encoded data.</param>
    /// <returns>A byte array of the decoded string.</returns>
    /// <exception cref="Exception"></exception>
    public static byte[] HexToBinary(string hex)
    {
      var span = new Span<byte>(new byte[hex.Length >> 1]);

      HexToBinary(ref span, hex);

      return span.ToArray();
    }

    /// <summary>Converts a hex-encoded string to a byte array.</summary>
    /// <param name="target">The buffer to write decoded data to.</param>
    /// <param name="hex">Hex-encoded data.</param>
    /// <returns>The length of the encoded-string.</returns>
    /// <exception cref="Exception"></exception>
    public static int HexToBinary(ref Span<byte> target, string hex)
    {
      return HexToBinaryImpl(ref target, hex);
    }

    private static unsafe int HexToBinaryImpl(ref Span<byte> target, string hex)
    {
      const string IGNORED_CHARS = ":- ";

      fixed (byte* bin = &target.GetPinnableReference())
      {
        //we call sodium_hex2bin with some chars to be ignored
        var ret = SodiumLibrary.sodium_hex2bin(bin, target.Length, hex, hex.Length, IGNORED_CHARS,
          out var binLength, null);
        if (ret != 0)
        {
          throw new Exception("Internal error, decoding failed.");
        }

        //remove the trailing nulls from the array, if there were some format characters in the hex string before
        if (binLength != target.Length)
        {
          target = target.Slice(0, binLength);
        }

        return binLength;
      }
    }

    /// <summary>
    /// Takes an unsigned number, and increments it.
    /// </summary>
    /// <param name="value">The value to increment.</param>
    /// <returns>The incremented value.</returns>
    public static byte[] Increment(byte[] value)
    {
      var span = value.AsSpan();
      Increment(span);
      return span.ToArray();
    }

    /// <summary>
    /// Takes an unsigned number, and increments it.
    /// </summary>
    /// <param name="value">The value to increment.</param>
    /// <returns>The incremented value.</returns>
    public static void Increment(Span<byte> value)
    {
      unsafe
      {
        fixed (byte* buffer = &value.GetPinnableReference())
        {
          SodiumLibrary.sodium_increment(buffer, value.Length);
        }
      }
    
    }

    /// <summary>
    /// Compares two values in constant time.
    /// </summary>
    /// <param name="a">The first value.</param>
    /// <param name="b">The second value.</param>
    /// <returns><c>true</c> if the values are equal, otherwise <c>false</c></returns>
    public static bool Compare(byte[] a, byte[] b)
    {
      return Compare(a.AsSpan(), b.AsSpan());
    }

    /// <summary>
    /// Compares two values in constant time.
    /// </summary>
    /// <param name="a">The first value.</param>
    /// <param name="b">The second value.</param>
    /// <returns><c>true</c> if the values are equal, otherwise <c>false</c></returns>
    public static bool Compare(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
      unsafe
      {
        fixed (byte* ptrA = &a.GetPinnableReference())
        {
          fixed (byte* ptrB = &b.GetPinnableReference())
          {
            var ret = SodiumLibrary.sodium_compare(ptrA, ptrB, a.Length);

            return ret == 0;
          }
        }
      }
    }

    internal struct MessageRef
    {
      public readonly unsafe byte* Ptr;
      public readonly long Length;
      public readonly Encoding Encoding;
      public readonly unsafe byte* Ref1;
      public readonly unsafe byte* Ref2;

      public unsafe MessageRef(byte* ptr, long length, Encoding encoding, byte* ref1 = null, byte* ref2 = null)
      {
        Ptr = ptr;
        Length = length;
        Encoding = encoding;
        Ref1 = ref1;
        Ref2 = ref2;
        Ptr = ptr;
      }
    }

    internal static void WithMessageSpan(this ReadOnlySpan<char> message, Encoding encoding, ReadOnlySpan<byte> ref1, ReadOnlySpan<byte> ref2, Action<MessageRef> action)
    {
      unsafe
      {
        fixed (char* c = &message.GetPinnableReference())
        {
          var minLength = encoding.GetByteCount(c, message.Length);

          var temp = Pool.Rent(minLength);

          var sized = temp.AsSpan().Slice(0, minLength);

          fixed (byte* b = &sized.GetPinnableReference())
          {
            try
            {
              encoding.GetBytes(c, message.Length, b, minLength);

              fixed (byte* r1 = ref1)
              {
                fixed (byte* r2 = ref2)
                {
                  action(new MessageRef(b, message.Length, encoding, r1, r2));
                }
              }
            }
            finally
            {
              Pool.Return(temp);
            }
          }
        }
      }
    }

    internal static void WithMessageSpan(this ReadOnlySpan<char> message, Encoding encoding, ReadOnlySpan<byte> ref1, Action<MessageRef> action)
    {
      unsafe
      {
        fixed (char* c = &message.GetPinnableReference())
        {
          var minLength = encoding.GetByteCount(c, message.Length);

          var temp = Pool.Rent(minLength);

          var sized = temp.AsSpan().Slice(0, minLength);

          fixed (byte* b = &sized.GetPinnableReference())
          {
            try
            {
              encoding.GetBytes(c, message.Length, b, minLength);

              fixed (byte* r1 = ref1)
              {
                action(new MessageRef(b, message.Length, encoding, r1));
              }
            }
            finally
            {
              Pool.Return(temp);
            }
          }
        }
      }
    }
  }
}

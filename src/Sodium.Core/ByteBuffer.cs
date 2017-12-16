using System;
using System.Security.Cryptography;

namespace Sodium
{
    internal static class ByteBuffer
    {
        public static byte[] Create(int length) => new byte[length];
        public static byte[] Create(long length) => new byte[length];

        private static T Use<T>(int length, Func<byte[], T> func) => func(Create(length));
        private static T Use<T>(long length, Func<byte[], T> func) => func(Create(length));

        public static byte[] Use(int length, Action<byte[]> action)
        {
            return Use(length, buffer => {
                action(buffer);
                return buffer;
            });
        }

        public static byte[] Use(long length, Action<byte[]> action)
        {
            return Use(length, buffer => {
                action(buffer);
                return buffer;
            });
        }

        public static byte[] Use(int length, Func<byte[], int> func, string exceptionMessage)
        {
            return Use(length, buffer => {
                if (func(buffer) != 0)
                    throw new CryptographicException(exceptionMessage);

                return buffer;
            });
        }

        public static byte[] Use(long length, Func<byte[], int> func, string exceptionMessage)
        {
            return Use(length, buffer => {
                if (func(buffer) != 0)
                    throw new CryptographicException(exceptionMessage);

                return buffer;
            });
        }

        public static byte[] Slice(byte[] source, int index = 0, int? length = null, Action<byte[]> action = null)
        {
            return Use(length.GetValueOrDefault(source.Length - index), buffer => {
                Buffer.BlockCopy(source, index, buffer, 0, buffer.Length);
                action?.Invoke(buffer);
                return buffer;
            });
        }

        public static byte[] Slice(byte[] source, int index = 0, long? length = null, Action<byte[]> action = null)
        {
            return Use(length.GetValueOrDefault(source.Length - index), buffer => {
                Buffer.BlockCopy(source, index, buffer, 0, buffer.Length);
                action?.Invoke(buffer);
                return buffer;
            });
        }
    }
}

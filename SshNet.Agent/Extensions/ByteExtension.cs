using System;
using System.Numerics;

namespace SshNet.Agent.Extensions
{
    internal static class ByteExtension
    {
        public static BigInteger ToBigInteger2(this byte[] data)
        {
            if ((data[0] & (1 << 7)) == 0)
                return data.ToBigInteger();
            var buf = new byte[data.Length + 1];
            Buffer.BlockCopy(data, 0, buf, 1, data.Length);
            data = buf;
            return data.ToBigInteger();
        }

        private static BigInteger ToBigInteger(this byte[] data)
        {
            var reversed = new byte[data.Length];
            Buffer.BlockCopy(data, 0, reversed, 0, data.Length);
            return new BigInteger(reversed.Reverse());
        }

        public static T[] Reverse<T>(this T[] array)
        {
            Array.Reverse(array);
            return array;
        }
    }
}
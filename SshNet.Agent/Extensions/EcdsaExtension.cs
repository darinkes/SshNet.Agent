using System;
using System.Security.Cryptography;

namespace SshNet.Agent.Extensions
{
    internal static class EcdsaExtension
    {
        // EcParameters.Curve.Oid.FriendlyName returns with a P instead of p
        public static string EcCurveNameSshCompat(this ECDsa ecdsa)
        {
            return ecdsa.KeySize switch
            {
                256 => "nistp256",
                384 => "nistp384",
                521 => "nistp521",
                _ => throw new CryptographicException("Unsupported KeyLength")
            };
        }

        public static byte[] UncompressedCoords(this ECParameters ecdsaParameters)
        {
            var q = new byte[1 + ecdsaParameters.Q.X.Length + ecdsaParameters.Q.Y.Length];
            Buffer.SetByte(q, 0, 4); // Uncompressed
            Buffer.BlockCopy(ecdsaParameters.Q.X, 0, q, 1, ecdsaParameters.Q.X.Length);
            Buffer.BlockCopy(ecdsaParameters.Q.Y, 0, q, ecdsaParameters.Q.X.Length + 1, ecdsaParameters.Q.Y.Length);
            return q;
        }
    }
}
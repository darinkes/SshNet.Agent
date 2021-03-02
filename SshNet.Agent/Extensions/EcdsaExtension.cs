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

        public static int EcCoordsLength(this ECDsa ecdsa)
        {
            return ecdsa.KeySize switch
            {
                256 => 32,
                384 => 48,
                521 => 66,
                _ => throw new CryptographicException("Unsupported KeyLength")
            };
        }

        public static byte[] UncompressedCoords(this ECParameters ecdsaParameters, int coordLength)
        {
            var q = new byte[1 + 2 * coordLength];
            var qx = ecdsaParameters.Q.X.Pad(coordLength);
            var qy = ecdsaParameters.Q.Y.Pad(coordLength);

            Buffer.SetByte(q, 0, 4); // Uncompressed
            Buffer.BlockCopy(qx, 0, q, 1, qx.Length);
            Buffer.BlockCopy(qy, 0, q, coordLength + 1, qy.Length);
            return q;
        }
    }
}
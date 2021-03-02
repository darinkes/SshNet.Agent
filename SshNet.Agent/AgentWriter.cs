using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using SshNet.Agent.Extensions;

namespace SshNet.Agent
{
    internal class AgentWriter : BinaryWriter
    {
        public AgentWriter(Stream stream) : base(stream, Encoding.Default, true)
        {
        }

        public override void Write(uint value)
        {
            var data = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);
            base.Write(data);
        }

        public void EncodeUInt(uint i)
        {
            var data = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);
            base.Write(data);
        }

        public void EncodeBignum2(byte[] data)
        {
            EncodeUInt((uint)data.Length);
            base.Write(data);
        }

        public void EncodeString(string str)
        {
            EncodeString(Encoding.ASCII.GetBytes(str));
        }

        public void EncodeString(byte[] str)
        {
            EncodeUInt((uint)str.Length);
            base.Write(str);
        }

        public void EncodeEcKey(ECDsa ecdsa)
        {
            var ecdsaParameters = ecdsa.ExportParameters(true);
            EncodeString(ecdsa.EcCurveNameSshCompat());
            EncodeString(ecdsaParameters.UncompressedCoords(ecdsa.EcCoordsLength()));
            EncodeBignum2(ecdsaParameters.D.ToBigInteger2().ToByteArray().Reverse());
        }
    }
}
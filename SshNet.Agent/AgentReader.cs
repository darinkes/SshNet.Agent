using System;
using System.IO;
using System.Text;
using Renci.SshNet.Common;

namespace SshNet.Agent
{
    public class AgentReader : BinaryReader
    {
        public AgentReader(Stream input) : base(input, Encoding.Default, true)
        {
        }

        public override uint ReadUInt32()
        {
            var data = base.ReadBytes(4);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);
            return BitConverter.ToUInt32(data);
        }

        public byte[] ReadStringAsBytes()
        {
            var len = (int)ReadUInt32();
            return base.ReadBytes(len);
        }

        public override string ReadString()
        {
            return Encoding.Default.GetString(ReadStringAsBytes());
        }

        public BigInteger ReadBignum()
        {
            var data = ReadStringAsBytes();
            return new BigInteger(data.Reverse());
        }

        public byte[] ReadBignum2()
        {
            return ReadStringAsBytes();
        }
    }
}
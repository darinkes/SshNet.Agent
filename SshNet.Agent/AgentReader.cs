using System;
using System.IO;
using System.Text;
using Renci.SshNet.Common;
using SshNet.Agent.Extensions;

namespace SshNet.Agent
{
    internal class AgentReader : BinaryReader
    {
#if NETSTANDARD
        public AgentReader(Stream input) : base(input, Encoding.Default, true)
#else
        public AgentReader(Stream input) : base(input, Encoding.Default)
#endif
        {
        }

        public override uint ReadUInt32()
        {
            var data = base.ReadBytes(4);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);
            return BitConverter.ToUInt32(data, 0);
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
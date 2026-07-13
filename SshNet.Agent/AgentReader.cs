using System;
using System.IO;
using System.Text;

namespace SshNet.Agent
{
    internal class AgentReader : BinaryReader
    {
        public AgentReader(Stream input) : base(input, Encoding.UTF8, leaveOpen: true)
        {
        }

        public override uint ReadUInt32()
        {
            var data = base.ReadBytes(4);
            if (data.Length < 4)
                throw new EndOfStreamException("The agent closed the connection mid-message");
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
            return Encoding.UTF8.GetString(ReadStringAsBytes());
        }
    }
}

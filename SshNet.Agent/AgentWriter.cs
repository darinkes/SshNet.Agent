using System;
using System.IO;
using System.Text;

namespace SshNet.Agent
{
    internal class AgentWriter : BinaryWriter
    {
        public AgentWriter(Stream stream) : base(stream, Encoding.UTF8, leaveOpen: true)
        {
        }

        public override void Write(uint value)
        {
            var data = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);
            base.Write(data);
        }

        public void EncodeBignum2(byte[] data)
        {
            EncodeString(data);
        }

        public void EncodeString(string str)
        {
            EncodeString(Encoding.UTF8.GetBytes(str));
        }

        public void EncodeString(byte[] str)
        {
            Write((uint)str.Length);
            base.Write(str);
        }
    }
}

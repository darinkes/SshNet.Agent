﻿using System;
using System.IO;
using System.Text;

namespace SshNet.Agent
{
    internal class AgentWriter : BinaryWriter
    {
#if NETSTANDARD
        public AgentWriter(Stream stream) : base(stream, Encoding.Default, true)
#else
        public AgentWriter(Stream stream) : base(stream, Encoding.Default)
#endif
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
    }
}
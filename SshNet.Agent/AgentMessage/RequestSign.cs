using System;
using System.IO;
using SshNet.Agent.Keys;

namespace SshNet.Agent.AgentMessage
{
    internal class RequestSign : IAgentMessage
    {
        private readonly AgentKey _key;
        private readonly byte[] _data;

        public RequestSign(AgentKey key, byte[] data)
        {
            _key = key;
            _data = data;
        }

        public void To(AgentWriter writer)
        {
            writer.Write((uint)(1 + 4 + _data.Length + 4 + _key.KeyData.Length + 4));
            writer.Write((byte)AgentMessageType.SSH2_AGENTC_SIGN_REQUEST);
            writer.Write((uint)_key.KeyData.Length);
            writer.Write(_key.KeyData);
            writer.Write((uint)_data.Length);
            writer.Write(_data);
            writer.Write((uint)0);
        }

        public object From(AgentReader reader)
        {
            _ = reader.ReadUInt32(); // msglen
            var answer = (AgentMessageType)reader.ReadByte();
            if (answer != AgentMessageType.SSH2_AGENT_SIGN_RESPONSE)
                throw new Exception($"Wrong Answer {answer}");

            var signatureData = reader.ReadStringAsBytes();
            using var signatureStream = new MemoryStream(signatureData);
            using var signatureReader = new AgentReader(signatureStream);

            // identifier
            _ = signatureReader.ReadString();
            return signatureReader.ReadStringAsBytes();
        }
    }
}
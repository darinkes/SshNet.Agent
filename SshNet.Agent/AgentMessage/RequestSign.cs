using System;
using System.IO;
using SshNet.Agent.Keys;

namespace SshNet.Agent.AgentMessage
{
    internal class RequestSign : IAgentMessage
    {
        private readonly IAgentKey _key;
        private readonly byte[] _data;
        private readonly uint _flags;

        public RequestSign(IAgentKey key, byte[] data, uint flags = 0)
        {
            _key = key;
            _data = data;
            _flags = flags;
        }

        public void To(AgentWriter writer)
        {
            using var signStream = new MemoryStream();
            using var signWriter = new AgentWriter(signStream);
            signWriter.EncodeString(_key.KeyData);
            signWriter.EncodeString(_data);
            signWriter.Write(_flags);
            var signData = signStream.ToArray();

            writer.Write((uint)(1 + signData.Length));
            writer.Write((byte)AgentMessageType.SSH2_AGENTC_SIGN_REQUEST);
            writer.Write(signData);
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
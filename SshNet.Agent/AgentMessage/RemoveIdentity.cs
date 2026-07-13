using System;
using System.IO;

namespace SshNet.Agent.AgentMessage
{
    internal class RemoveIdentity : IAgentMessage
    {
        private readonly byte[]? _keyBlob;

        public RemoveIdentity()
        {
        }

        public RemoveIdentity(byte[] keyBlob)
        {
            _keyBlob = keyBlob;
        }

        public void To(AgentWriter writer)
        {
            if (_keyBlob is null)
            {
                writer.Write((uint) 1);
                writer.Write((byte) AgentMessageType.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
                return;
            }

            using var keyStream = new MemoryStream();
            using var keyWriter = new AgentWriter(keyStream);
            keyWriter.EncodeString(_keyBlob);
            var keyData = keyStream.ToArray();

            writer.Write((uint) (1 + keyData.Length));
            writer.Write((byte) AgentMessageType.SSH2_AGENTC_REMOVE_IDENTITY);
            writer.Write(keyData);
        }

        public object? From(AgentReader reader)
        {
            _ = reader.ReadUInt32(); // msglen
            var answer = (AgentMessageType)reader.ReadByte();
            if (answer != AgentMessageType.SSH_AGENT_SUCCESS)
                throw new SshAgentFailureException($"The agent answered {answer} instead of SSH_AGENT_SUCCESS");
            return null;
        }
    }
}
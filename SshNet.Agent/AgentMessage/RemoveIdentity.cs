#nullable enable
using System;
using System.IO;
using SshNet.Agent.Keys;

namespace SshNet.Agent.AgentMessage
{
    internal class RemoveIdentity : IAgentMessage
    {
        private readonly IAgentKey? _agentKey;

        public RemoveIdentity()
        {
        }

        public RemoveIdentity(IAgentKey agentKey)
        {
            _agentKey = agentKey;
        }

        public void To(AgentWriter writer)
        {
            if (_agentKey is null)
            {
                writer.Write((uint) 1);
                writer.Write((byte) AgentMessageType.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
                return;
            }

            using var keyStream = new MemoryStream();
            using var keyWriter = new AgentWriter(keyStream);
            keyWriter.EncodeString(_agentKey.KeyData);
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
                throw new Exception($"Wrong Answer {answer}");
            return null;
        }
    }
}
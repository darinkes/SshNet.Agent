using System;
using System.IO;

namespace SshNet.Agent.AgentMessage
{
    internal class LockAgent : IAgentMessage
    {
        private readonly bool _lock;
        private readonly string _passphrase;

        public LockAgent(bool @lock, string passphrase)
        {
            _lock = @lock;
            _passphrase = passphrase;
        }

        public void To(AgentWriter writer)
        {
            using var lockStream = new MemoryStream();
            using var lockWriter = new AgentWriter(lockStream);
            lockWriter.EncodeString(_passphrase);
            var lockData = lockStream.ToArray();

            writer.Write((uint)(1 + lockData.Length));
            writer.Write((byte)(_lock ? AgentMessageType.SSH_AGENTC_LOCK : AgentMessageType.SSH_AGENTC_UNLOCK));
            writer.Write(lockData);
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

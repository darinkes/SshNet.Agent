using System;

namespace SshNet.Agent.AgentMessage
{
    enum RemoveIdentityMode
    {
        All
    }

    internal class RemoveIdentity : IAgentMessage
    {
        private readonly RemoveIdentityMode _mode;

        public RemoveIdentity(RemoveIdentityMode mode)
        {
            _mode = mode;
        }

        public void To(AgentWriter writer)
        {
            if (_mode == RemoveIdentityMode.All)
            {
                writer.Write((uint) 1);
                writer.Write((byte) AgentMessageType.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
            }
        }

        public object From(AgentReader reader)
        {
            _ = reader.ReadUInt32(); // msglen
            var answer = (AgentMessageType)reader.ReadByte();
            if (answer != AgentMessageType.SSH_AGENT_SUCCESS)
                throw new Exception($"Wrong Answer {answer}");
            return null;
        }
    }
}
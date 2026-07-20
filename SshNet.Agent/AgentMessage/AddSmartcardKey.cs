using System;
using System.IO;

namespace SshNet.Agent.AgentMessage
{
    internal class AddSmartcardKey : IAgentMessage
    {
        // draft-miller-ssh-agent, "Key Constraints"
        private const byte ConstrainLifetime = 1;
        private const byte ConstrainConfirm = 2;

        private readonly string _providerId;
        private readonly string _pin;
        private readonly TimeSpan? _lifetime;
        private readonly bool _confirm;

        public AddSmartcardKey(string providerId, string pin, TimeSpan? lifetime = null, bool confirm = false)
        {
            _providerId = providerId;
            _pin = pin;
            _lifetime = lifetime;
            _confirm = confirm;
        }

        public void To(AgentWriter writer)
        {
            using var keyStream = new MemoryStream();
            using var keyWriter = new AgentWriter(keyStream);

            keyWriter.EncodeString(_providerId);
            keyWriter.EncodeString(_pin);

            var messageType = AgentMessageType.SSH_AGENTC_ADD_SMARTCARD_KEY;
            if (_lifetime is not null || _confirm)
            {
                messageType = AgentMessageType.SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED;
                if (_lifetime is not null)
                {
                    keyWriter.Write(ConstrainLifetime);
                    keyWriter.Write(Convert.ToUInt32(_lifetime.Value.TotalSeconds));
                }
                if (_confirm)
                    keyWriter.Write(ConstrainConfirm);
            }
            var keyData = keyStream.ToArray();

            writer.Write((uint)(1 + keyData.Length));
            writer.Write((byte)messageType);
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

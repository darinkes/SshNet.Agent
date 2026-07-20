using System.IO;

namespace SshNet.Agent.AgentMessage
{
    internal class RemoveSmartcardKey : IAgentMessage
    {
        private readonly string _providerId;
        private readonly string _pin;

        public RemoveSmartcardKey(string providerId, string pin)
        {
            _providerId = providerId;
            _pin = pin;
        }

        public void To(AgentWriter writer)
        {
            using var keyStream = new MemoryStream();
            using var keyWriter = new AgentWriter(keyStream);
            keyWriter.EncodeString(_providerId);
            keyWriter.EncodeString(_pin);
            var keyData = keyStream.ToArray();

            writer.Write((uint)(1 + keyData.Length));
            writer.Write((byte)AgentMessageType.SSH_AGENTC_REMOVE_SMARTCARD_KEY);
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

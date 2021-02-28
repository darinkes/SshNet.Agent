using Renci.SshNet.Security.Cryptography;

namespace SshNet.Agent.Keys
{
    public class AgentSignature : DigitalSignature
    {
        private readonly Agent _agent;
        private readonly AgentKey _agentKey;

        public AgentSignature(Agent agent, AgentKey agentKey)
        {
            _agent = agent;
            _agentKey = agentKey;
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            throw new System.NotImplementedException();
        }

        public override byte[] Sign(byte[] input)
        {
            return _agent.Sign(_agentKey, input);
        }
    }
}
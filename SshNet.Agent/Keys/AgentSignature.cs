using Renci.SshNet.Security.Cryptography;

namespace SshNet.Agent.Keys
{
    internal class AgentSignature : DigitalSignature
    {
        private readonly SshAgent _agent;
        private readonly IAgentKey _agentKey;

        public AgentSignature(SshAgent agent, IAgentKey agentKey)
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
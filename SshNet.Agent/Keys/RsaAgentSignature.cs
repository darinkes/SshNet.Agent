using System.Security.Cryptography;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Agent.Keys
{
    internal class RsaAgentSignature : DigitalSignature
    {
        private readonly SshAgent _agent;
        private readonly IAgentKey _agentKey;
        private readonly HashAlgorithmName _hashAlgorithmName;

        public RsaAgentSignature(SshAgent agent, RsaAgentKey agentKey)
            : this(agent, agentKey, HashAlgorithmName.SHA1)
        {
        }

        public RsaAgentSignature(SshAgent agent, RsaAgentKey agentKey, HashAlgorithmName hashAlgorithmName)
        {
            _agent = agent;
            _agentKey = agentKey;
            _hashAlgorithmName = hashAlgorithmName;
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            throw new System.NotImplementedException();
        }

        public override byte[] Sign(byte[] input)
        {
            uint flags = 0;
            if (_hashAlgorithmName == HashAlgorithmName.SHA256)
                flags = 2; // SSH_AGENT_RSA_SHA2_256
            else if (_hashAlgorithmName == HashAlgorithmName.SHA512)
                flags = 4; // SSH_AGENT_RSA_SHA2_512

            return _agent.Sign(_agentKey, input, flags);
        }
    }
}
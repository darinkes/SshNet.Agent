using Renci.SshNet.Common;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Agent.Keys
{
    internal class RsaAgentKey : RsaKey, IAgentKey
    {
        public byte[] KeyData { get; }

        public Agent Agent { get; }

        private AgentSignature? _signature;
        protected override DigitalSignature DigitalSignature
        {
            get
            {
                if (_signature is null)
                {
                    _signature = new AgentSignature(Agent, this);
                }

                return _signature;
            }
        }

        public RsaAgentKey(BigInteger modulus, BigInteger exponent, Agent agent, byte[] keyData)
        {
            KeyData = keyData;
            Agent = agent;
            _privateKey = new BigInteger[2];
            _privateKey[0] = modulus;
            _privateKey[1] = exponent;
        }
    }
}
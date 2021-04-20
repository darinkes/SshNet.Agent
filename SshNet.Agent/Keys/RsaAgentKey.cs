using Renci.SshNet.Common;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Agent.Keys
{
    public class RsaAgentKey : RsaKey, IAgentKey
    {
        public byte[] KeyData { get; }

        public SshAgent Agent { get; }

        private AgentSignature? _signature;
        protected override DigitalSignature DigitalSignature
        {
            get { return _signature ??= new AgentSignature(Agent, this); }
        }

        public RsaAgentKey(BigInteger modulus, BigInteger exponent, SshAgent agent, byte[] keyData)
        {
            KeyData = keyData;
            Agent = agent;
            _privateKey = new BigInteger[2];
            _privateKey[0] = modulus;
            _privateKey[1] = exponent;
        }
    }
}
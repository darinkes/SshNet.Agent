using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Agent.Keys
{
    internal class RsaAgentKey : RsaKey, IAgentKey
    {
        public byte[] KeyData { get; }

        public SshAgent Agent { get; }

        private DigitalSignature? _signature;
        protected override DigitalSignature DigitalSignature
        {
            get { return _signature ??= new RsaAgentSignature(Agent, this); }
        }

        public RsaAgentKey(SshAgent agent, byte[] keyData) : base(new SshKeyData(keyData))
        {
            KeyData = keyData;
            Agent = agent;
        }
    }
}
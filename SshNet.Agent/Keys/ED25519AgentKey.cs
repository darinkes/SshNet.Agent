using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Agent.Keys
{
    internal class ED25519AgentKey : ED25519Key, IAgentKey
    {
        public byte[] KeyData { get; }

        public SshAgent Agent { get; }

        private AgentSignature? _signature;
        protected override DigitalSignature DigitalSignature
        {
            get { return _signature ??= new AgentSignature(Agent, this); }
        }

        public ED25519AgentKey(SshAgent agent, byte[] keyData) : base(new SshKeyData(keyData))
        {
            Agent = agent;
            KeyData = keyData;
        }
    }
}
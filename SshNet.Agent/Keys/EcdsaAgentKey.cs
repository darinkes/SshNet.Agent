using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Agent.Keys
{
    internal class EcdsaAgentKey : EcdsaKey, IAgentKey
    {
        public byte[] KeyData { get; }

        public SshAgent Agent { get; }

        private AgentSignature? _signature;
        protected override DigitalSignature DigitalSignature
        {
            get { return _signature ??= new AgentSignature(Agent, this); }
        }

        public EcdsaAgentKey(SshAgent agent, byte[] keyData) : base(new SshKeyData(keyData))
        {
            KeyData = keyData;
            Agent = agent;
        }
    }
}
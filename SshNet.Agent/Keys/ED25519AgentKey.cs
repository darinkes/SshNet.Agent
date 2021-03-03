#nullable enable
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Agent.Keys
{
    public class ED25519AgentKey : ED25519Key, IAgentKey
    {
        public byte[] KeyData { get; }

        public SshAgent Agent { get; }

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

        public ED25519AgentKey(byte[] pk, SshAgent agent, byte[] keyData) : base(pk)
        {
            Agent = agent;
            KeyData = keyData;
        }
    }
}
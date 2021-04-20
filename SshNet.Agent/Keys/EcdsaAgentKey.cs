using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Agent.Keys
{
    public class EcdsaAgentKey : EcdsaKey, IAgentKey
    {
        public byte[] KeyData { get; }

        public SshAgent Agent { get; }

        private AgentSignature? _signature;
        protected override DigitalSignature DigitalSignature
        {
            get { return _signature ??= new AgentSignature(Agent, this); }
        }

        public EcdsaAgentKey(string curve, byte[] uncompressedCoords, SshAgent agent, byte[] keyData)
            : base(curve, uncompressedCoords, null)
        {
            KeyData = keyData;
            Agent = agent;
        }
    }
}
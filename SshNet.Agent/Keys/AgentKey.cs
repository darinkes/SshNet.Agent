using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Agent.Keys
{
    public abstract class AgentKey : Key
    {
        public byte[] KeyData { get; private set; }

        private Agent Agent { get; }

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

        protected AgentKey(Agent agent, byte[] keyData)
        {
            Agent = agent;
            KeyData = keyData;
        }
    }
}
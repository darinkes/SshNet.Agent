using Renci.SshNet;

namespace SshNet.Agent
{
    public record AgentIdentity
    {
        public string Comment { get; set; }
        public PrivateKeyFile Key { get; set; }
    }
}
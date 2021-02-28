using Renci.SshNet;

namespace SshNet.Agent
{
    public record AgentIdentity
    {
        public string Comment { get; init; }
        public PrivateKeyFile Key { get; init; }
    }
}
namespace SshNet.Agent.Keys
{
    public interface IAgentKey
    {
        public byte[] KeyData { get; }

        public SshAgent Agent { get; }
    }
}
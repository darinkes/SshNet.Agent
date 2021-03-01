namespace SshNet.Agent.Keys
{
    public interface IAgentKey
    {
        public byte[] KeyData { get; }

        public Agent Agent { get; }
    }
}
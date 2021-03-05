namespace SshNet.Agent.Keys
{
    internal interface IAgentKey
    {
        public byte[] KeyData { get; }

        public SshAgent Agent { get; }
    }
}
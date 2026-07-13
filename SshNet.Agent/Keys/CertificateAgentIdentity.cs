namespace SshNet.Agent.Keys
{
    /// <summary>
    /// The agent identity behind a certificate: signing echoes the certificate
    /// blob back to the agent, which signs with the matching private key.
    /// </summary>
    internal class CertificateAgentIdentity : IAgentKey
    {
        public byte[] KeyData { get; }

        public SshAgent Agent { get; }

        public CertificateAgentIdentity(SshAgent agent, byte[] keyData)
        {
            Agent = agent;
            KeyData = keyData;
        }
    }
}

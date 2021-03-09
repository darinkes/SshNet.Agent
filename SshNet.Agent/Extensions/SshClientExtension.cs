#if NETSTANDARD2_1
using Renci.SshNet;

namespace SshNet.Agent.Extensions
{
    public static class SshClientExtension
    {
        public static SshAgentForwarding ForwardAgent(this SshClient sshClient, SshAgent sshAgent, string remotePath = "")
        {
            var forwarding = sshAgent.Forward(remotePath);
            sshClient.AddForwardedPort(forwarding.ForwardedPort);
            forwarding.Start();
            return forwarding;
        }
    }
}
#endif
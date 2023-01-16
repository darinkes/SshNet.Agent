using Renci.SshNet;
using Renci.SshNet.Security;

namespace SshNet.Agent
{
    public class PrivateKeyAgent : IPrivateKeySource
    {
        public HostAlgorithm HostKey { get; }

        public PrivateKeyAgent(Key key)
        {
            HostKey = new KeyHostAlgorithm(key.ToString(), key);
        }
    }
}
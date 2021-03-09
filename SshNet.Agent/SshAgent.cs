using System;
using System.Collections.Generic;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Agent.AgentMessage;
using SshNet.Agent.Keys;

namespace SshNet.Agent
{
    public class SshAgent
    {
        public string SocketPath { get; }

        public SshAgent()
            : this(Environment.GetEnvironmentVariable("SSH_AUTH_SOCK") ?? "openssh-ssh-agent")
        {
        }

        public SshAgent(string socketPath)
        {
            SocketPath = socketPath;
        }

        public IEnumerable<AgentIdentity> RequestIdentities()
        {
            var list = Send(new RequestIdentities(this));
            if (list is null)
                return new List<AgentIdentity>();
            return (IEnumerable<AgentIdentity>)list;
        }

        public void RemoveAllIdentities()
        {
            _ = Send(new RemoveIdentity());
        }

        public void RemoveIdentities(IEnumerable<PrivateKeyFile> privateKeyFiles)
        {
            foreach (var privateKeyFile in privateKeyFiles)
            {
                RemoveIdentity(privateKeyFile);
            }
        }

        public void RemoveIdentity(PrivateKeyFile privateKeyFile)
        {
            if (!(((KeyHostAlgorithm)privateKeyFile.HostKey).Key is IAgentKey agentKey))
                throw new ArgumentException("Just AgentKeys can be removed");

            _ = Send(new RemoveIdentity(agentKey));
        }

        public void AddIdentity(PrivateKeyFile keyFile)
        {
            _ = Send(new AddIdentity(keyFile));
        }

#if NETSTANDARD2_1
        public SshAgentForwarding Forward(string remotePath = "")
        {
            return new SshAgentForwarding(this, remotePath);
        }
#endif

        internal byte[] Sign(IAgentKey key, byte[] data)
        {
            var signature = Send(new RequestSign(key, data));
            if (signature is null)
                return new byte[0];
            return (byte[])signature;
        }

        internal virtual object? Send(IAgentMessage message)
        {
            using var socketStream = new SshAgentSocketStream(SocketPath);
            using var writer = new AgentWriter(socketStream);
            using var reader = new AgentReader(socketStream);

            message.To(writer);
            return message.From(reader);
        }
    }
}
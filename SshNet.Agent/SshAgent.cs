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
        private readonly string _socketPath;

        public SshAgent() : this(AgentSocketPath.GetPath())
        {
        }

        public SshAgent(string socketPath)
        {
            _socketPath = socketPath;
        }

        public IEnumerable<AgentIdentity> RequestIdentities()
        {
            return (IEnumerable<AgentIdentity>)Send(new RequestIdentities(this));
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
            var agentKey = ((KeyHostAlgorithm)privateKeyFile.HostKey).Key as IAgentKey;
            if (agentKey is null)
                throw new ArgumentException("Just AgentKeys can be removed");

            _ = Send(new RemoveIdentity(agentKey));
        }

        public void AddIdentity(PrivateKeyFile keyFile)
        {
            _ = Send(new AddIdentity(keyFile));
        }

        public byte[] Sign(IAgentKey key, byte[] data)
        {
            return (byte[])Send(new RequestSign(key, data));
        }

        internal virtual object Send(IAgentMessage message)
        {
            using var socketStream = new AgentSocketStream(_socketPath);
            using var writer = new AgentWriter(socketStream);
            using var reader = new AgentReader(socketStream);

            message.To(writer);
            return message.From(reader);
        }
    }
}
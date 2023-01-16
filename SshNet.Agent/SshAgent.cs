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

        public SshAgent()
            : this(Environment.GetEnvironmentVariable("SSH_AUTH_SOCK") ?? "openssh-ssh-agent")
        {
        }

        public SshAgent(string socketPath)
        {
            _socketPath = socketPath;
        }

        public PrivateKeyAgent[] RequestIdentities()
        {
            var list = Send(new RequestIdentities(this));
            if (list is null)
                return new PrivateKeyAgent[] {};
            return (PrivateKeyAgent[])list;
        }

        public void RemoveAllIdentities()
        {
            _ = Send(new RemoveIdentity());
        }

        public void RemoveIdentities(IEnumerable<PrivateKeyAgent> privateKeys)
        {
            foreach (var privateKey in privateKeys)
            {
                RemoveIdentity(privateKey);
            }
        }

        public void RemoveIdentity(PrivateKeyAgent privateAgentKey)
        {
            if (!(((KeyHostAlgorithm)privateAgentKey.HostKey).Key is IAgentKey agentKey))
                throw new ArgumentException("Just AgentKeys can be removed");
            _ = Send(new RemoveIdentity(agentKey));
        }

        public void AddIdentity(IPrivateKeySource keyFile)
        {
            _ = Send(new AddIdentity(keyFile));
        }

        internal byte[] Sign(IAgentKey key, byte[] data)
        {
            var signature = Send(new RequestSign(key, data));
            if (signature is null)
                return new byte[0];
            return (byte[])signature;
        }

        internal virtual object? Send(IAgentMessage message)
        {
            using var socketStream = new SshAgentSocketStream(_socketPath);
            using var writer = new AgentWriter(socketStream);
            using var reader = new AgentReader(socketStream);

            message.To(writer);
            return message.From(reader);
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Agent.AgentMessage;
using SshNet.Agent.Keys;

namespace SshNet.Agent
{
    public class SshAgent
    {
        private readonly string _socketPath;
        private readonly TimeSpan _timeout;

        /// <summary>
        /// Also offer the legacy ssh-rsa (SHA-1) algorithm for RSA identities, after
        /// rsa-sha2-512 and rsa-sha2-256. Only needed for servers without RFC 8332
        /// support (OpenSSH older than 7.2).
        /// </summary>
        public bool IncludeLegacySshRsa { get; set; }

        public SshAgent(TimeSpan? timeout = null)
            : this(Environment.GetEnvironmentVariable("SSH_AUTH_SOCK") ?? "openssh-ssh-agent", timeout)
        {
        }

        public SshAgent(string socketPath, TimeSpan? timeout)
        {
            _socketPath = socketPath;
            _timeout = timeout ?? TimeSpan.FromSeconds(10);
        }

        public SshAgentPrivateKey[] RequestIdentities()
        {
            var list = Send(new RequestIdentities(this));
            if (list is null)
                return new SshAgentPrivateKey[] {};
            return (SshAgentPrivateKey[])list;
        }

        public void RemoveAllIdentities()
        {
            _ = Send(new RemoveIdentity());
        }

        public void RemoveIdentities(IEnumerable<SshAgentPrivateKey> privateKeys)
        {
            foreach (var privateKey in privateKeys)
            {
                RemoveIdentity(privateKey);
            }
        }

        public void RemoveIdentity(SshAgentPrivateKey sshAgentPrivateKey)
        {
            if (((KeyHostAlgorithm)sshAgentPrivateKey.HostKeyAlgorithms.First()).Key is not IAgentKey agentKey)
                throw new ArgumentException("Just AgentKeys can be removed");
            _ = Send(new RemoveIdentity(agentKey));
        }

        public void AddIdentity(IPrivateKeySource keyFile)
        {
            _ = Send(new AddIdentity(keyFile));
        }

        internal byte[] Sign(IAgentKey key, byte[] data, uint flags = 0)
        {
            var signature = Send(new RequestSign(key, data, flags));
            if (signature is null)
                return Array.Empty<byte>();
            return (byte[])signature;
        }

        internal virtual object? Send(IAgentMessage message)
        {
            using var socketStream = new SshAgentSocketStream(_socketPath, _timeout);
            using var writer = new AgentWriter(socketStream);
            using var reader = new AgentReader(socketStream);

            message.To(writer);
            return message.From(reader);
        }
    }
}
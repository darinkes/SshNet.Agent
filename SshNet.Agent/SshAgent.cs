using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
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

        /// <summary>
        /// Locks the agent with the passphrase. A locked agent hides its
        /// identities and refuses signing until it is unlocked again.
        /// </summary>
        public void Lock(string passphrase)
        {
            _ = Send(new LockAgent(true, passphrase));
        }

        /// <summary>Unlocks an agent previously locked with <see cref="Lock"/>.</summary>
        public void Unlock(string passphrase)
        {
            _ = Send(new LockAgent(false, passphrase));
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
            // HostAlgorithm.Data is the blob the agent listed the identity
            // under - the key blob for plain keys, the certificate blob for
            // certificates
            _ = Send(new RemoveIdentity(sshAgentPrivateKey.HostKeyAlgorithms.First().Data));
        }

        public void AddIdentity(IPrivateKeySource keyFile)
        {
            _ = Send(new AddIdentity(keyFile));
        }

        /// <summary>
        /// Adds the key with constraints, like ssh-add -t/-c: the agent deletes
        /// the key again after <paramref name="lifetime"/>, and with
        /// <paramref name="confirm"/> it asks the user for confirmation on every
        /// use of the key.
        /// </summary>
        public void AddIdentity(IPrivateKeySource keyFile, TimeSpan? lifetime, bool confirm = false)
        {
            _ = Send(new AddIdentity(keyFile, lifetime, confirm));
        }

        internal byte[] Sign(IAgentKey key, byte[] data, uint flags = 0)
        {
            var signature = Send(new RequestSign(key, data, flags));
            if (signature is null)
                throw new SshAgentException("The agent did not return a signature");
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

        /// <summary>Async variant of <see cref="RequestIdentities"/>.</summary>
        public async Task<SshAgentPrivateKey[]> RequestIdentitiesAsync(CancellationToken cancellationToken = default)
        {
            var list = await SendAsync(new RequestIdentities(this), cancellationToken).ConfigureAwait(false);
            if (list is null)
                return new SshAgentPrivateKey[] {};
            return (SshAgentPrivateKey[])list;
        }

        /// <summary>Async variant of <see cref="AddIdentity"/>.</summary>
        public async Task AddIdentityAsync(IPrivateKeySource keyFile, CancellationToken cancellationToken = default)
        {
            _ = await SendAsync(new AddIdentity(keyFile), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Async variant of <see cref="RemoveIdentity"/>.</summary>
        public async Task RemoveIdentityAsync(SshAgentPrivateKey sshAgentPrivateKey, CancellationToken cancellationToken = default)
        {
            // HostAlgorithm.Data is the blob the agent listed the identity
            // under - the key blob for plain keys, the certificate blob for
            // certificates
            _ = await SendAsync(new RemoveIdentity(sshAgentPrivateKey.HostKeyAlgorithms.First().Data), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Async variant of <see cref="RemoveIdentities"/>.</summary>
        public async Task RemoveIdentitiesAsync(IEnumerable<SshAgentPrivateKey> privateKeys, CancellationToken cancellationToken = default)
        {
            foreach (var privateKey in privateKeys)
                await RemoveIdentityAsync(privateKey, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Async variant of <see cref="RemoveAllIdentities"/>.</summary>
        public async Task RemoveAllIdentitiesAsync(CancellationToken cancellationToken = default)
        {
            _ = await SendAsync(new RemoveIdentity(), cancellationToken).ConfigureAwait(false);
        }

        internal virtual async Task<object?> SendAsync(IAgentMessage message, CancellationToken cancellationToken)
        {
            // messages serialize into memory, so only the transport needs to be
            // asynchronous; the response is read completely before parsing
            byte[] request;
            using (var requestStream = new MemoryStream())
            {
                using (var writer = new AgentWriter(requestStream))
                {
                    message.To(writer);
                }
                request = requestStream.ToArray();
            }

            using var socketStream = await SshAgentSocketStream.ConnectAsync(_socketPath, _timeout, cancellationToken).ConfigureAwait(false);
            await socketStream.WriteAsync(request, 0, request.Length, cancellationToken).ConfigureAwait(false);
            var response = await ReadMessageAsync(socketStream, cancellationToken).ConfigureAwait(false);

            using var responseStream = new MemoryStream(response);
            using var reader = new AgentReader(responseStream);
            return message.From(reader);
        }

        private const int MaxMessageLength = 256 * 1024; // OpenSSH AGENT_MAX_MSGLEN

        /// <summary>
        /// Reads one agent message (uint32 length + payload) and returns it
        /// including the length prefix, which IAgentMessage.From expects to read.
        /// </summary>
        private static async Task<byte[]> ReadMessageAsync(Stream stream, CancellationToken cancellationToken)
        {
            var header = new byte[4];
            await ReadExactlyAsync(stream, header, 0, cancellationToken).ConfigureAwait(false);
            var length = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
            if (length < 1 || length > MaxMessageLength)
                throw new InvalidDataException($"Invalid agent message length {length}");

            var message = new byte[4 + length];
            Buffer.BlockCopy(header, 0, message, 0, 4);
            await ReadExactlyAsync(stream, message, 4, cancellationToken).ConfigureAwait(false);
            return message;
        }

        private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, int offset, CancellationToken cancellationToken)
        {
            while (offset < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer, offset, buffer.Length - offset, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    throw new EndOfStreamException("The agent closed the connection mid-message");
                offset += read;
            }
        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
#if NETFRAMEWORK || NET
using System.Security.AccessControl;
using System.Security.Principal;
#endif
using System.Threading;
using System.Threading.Tasks;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Agent.AgentMessage;
#if NETSTANDARD2_1 || NET
using System.Net.Sockets;
using System.Runtime.InteropServices;
#endif

namespace SshNet.Agent
{
    /// <summary>
    /// A minimal ssh-agent server: it holds SSH.NET keys and answers the agent
    /// protocol (list and sign) over a unix domain socket or a Windows named
    /// pipe, so any SSH client - including this library's own <see cref="SshAgent"/>
    /// - can use them. Signing is done with the in-process keys; this is the
    /// building block for HSM/Key Vault-backed agents and Pageant replacements.
    /// </summary>
    /// <remarks>
    /// Keys are added through the .NET API, not the agent protocol: a client
    /// SSH_AGENTC_ADD_IDENTITY request is answered with SSH_AGENT_FAILURE. Unix
    /// domain sockets need the netstandard2.1 or .NET build.
    /// <para>
    /// The endpoint is a signing authority: anyone who can connect to it can list
    /// the keys and use them to sign. Keep it private - on .NET 7 and later the
    /// unix socket is created owner-only, otherwise place it in a directory only
    /// you can access. The Windows named pipe is created with the default
    /// owner-scoped ACL.
    /// </para>
    /// </remarks>
    public sealed class SshAgentServer : IDisposable
    {
        private const uint RsaSha2_256 = 2;
        private const uint RsaSha2_512 = 4;

        private readonly List<IPrivateKeySource> _keys = new();
        private readonly object _sync = new();
        private readonly CancellationTokenSource _cts = new();
        private byte[]? _lockPassphrase;
        private Task? _listener;
#if NETSTANDARD2_1 || NET
        private string? _socketFile;
#endif

        /// <summary>The socket path or pipe name the server is listening on.</summary>
        public string? Endpoint { get; private set; }

        /// <summary>Creates a server holding the given keys.</summary>
        public SshAgentServer(params IPrivateKeySource[] keys)
        {
            _keys.AddRange(keys);
        }

        /// <summary>Adds a key the server offers and signs with.</summary>
        public void Add(IPrivateKeySource key)
        {
            lock (_sync)
                _keys.Add(key);
        }

        /// <summary>Removes a previously added key.</summary>
        public void Remove(IPrivateKeySource key)
        {
            lock (_sync)
                _keys.Remove(key);
        }

        /// <summary>
        /// Starts listening on <paramref name="endpoint"/>: a unix domain socket
        /// path off Windows, a named pipe name on Windows. Returns once the server
        /// is ready to accept connections.
        /// </summary>
        public void Start(string endpoint)
        {
            if (_listener is not null)
                throw new InvalidOperationException("The server is already started");
            Endpoint = endpoint;
#if NETSTANDARD2_1 || NET
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                listener.Bind(new UnixDomainSocketEndPoint(endpoint));
#if NET7_0_OR_GREATER
                // the socket is a signing authority; keep it usable only by the current user
                File.SetUnixFileMode(endpoint, UnixFileMode.UserRead | UnixFileMode.UserWrite);
#endif
                listener.Listen(16);
                _socketFile = endpoint;
                _listener = AcceptSocketsAsync(listener, _cts.Token);
                return;
            }
#endif
            if (!Environment.OSVersion.Platform.ToString().StartsWith("Win", StringComparison.OrdinalIgnoreCase))
                throw new PlatformNotSupportedException("Unix domain sockets need the netstandard2.1 or .NET build of SshNet.Agent");
            _listener = AcceptPipesAsync(endpoint, _cts.Token);
        }

        private async Task AcceptPipesAsync(string pipeName, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                var server = CreatePipe(pipeName);
                try
                {
                    await server.WaitForConnectionAsync(token).ConfigureAwait(false);
                }
                catch (Exception) when (token.IsCancellationRequested)
                {
                    server.Dispose();
                    return;
                }
                _ = ServeAsync(server, token);
            }
        }

        /// <summary>
        /// Creates the pipe restricted to the current user, so only the account
        /// running the server can reach this signing authority. Only ever called
        /// on Windows, where the pipe transport exists. On netstandard, which has
        /// no API to set the ACL at creation, the pipe's default owner-scoped
        /// security descriptor applies.
        /// </summary>
        private static NamedPipeServerStream CreatePipe(string pipeName)
        {
#if NETFRAMEWORK || NET
#pragma warning disable CA1416 // the pipe transport is only reached on Windows
            var security = new PipeSecurity();
            using var identity = WindowsIdentity.GetCurrent();
            security.AddAccessRule(new PipeAccessRule(identity.User!, PipeAccessRights.FullControl, AccessControlType.Allow));
#if NETFRAMEWORK
            return new NamedPipeServerStream(pipeName, PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous, 0, 0, security);
#else
            return NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous, 0, 0, security);
#endif
#pragma warning restore CA1416
#else
            return new NamedPipeServerStream(pipeName, PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
#endif
        }

#if NETSTANDARD2_1 || NET
        private async Task AcceptSocketsAsync(Socket listener, CancellationToken token)
        {
            using var abort = token.Register(listener.Dispose);
            while (!token.IsCancellationRequested)
            {
                Socket client;
                try
                {
                    client = await listener.AcceptAsync().ConfigureAwait(false);
                }
                catch
                {
                    return; // listener disposed on cancellation
                }
                _ = ServeAsync(new NetworkStream(client, ownsSocket: true), token);
            }
        }
#endif

        /// <summary>Serves one connection until the client closes it.</summary>
        private async Task ServeAsync(Stream stream, CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    var request = await ReadMessageAsync(stream, token).ConfigureAwait(false);
                    if (request is null)
                        return; // client hung up
                    var response = Handle(request);
                    var framed = Frame(response);
                    await stream.WriteAsync(framed, 0, framed.Length, token).ConfigureAwait(false);
                    await stream.FlushAsync(token).ConfigureAwait(false);
                }
            }
            catch (Exception)
            {
                // a broken connection must not take the server down
            }
            finally
            {
                stream.Dispose();
            }
        }

        /// <summary>Dispatches one request payload and returns the response payload.</summary>
        private byte[] Handle(byte[] request)
        {
            using var stream = new MemoryStream(request);
            using var reader = new AgentReader(stream);
            var type = (AgentMessageType)reader.ReadByte();

            lock (_sync)
            {
                var locked = _lockPassphrase is not null;
                switch (type)
                {
                    case AgentMessageType.SSH2_AGENTC_REQUEST_IDENTITIES:
                        return IdentitiesAnswer(locked);
                    case AgentMessageType.SSH2_AGENTC_SIGN_REQUEST:
                        return locked ? Failure() : SignResponse(reader);
                    case AgentMessageType.SSH2_AGENTC_REMOVE_IDENTITY:
                        return locked ? Failure() : RemoveIdentity(reader);
                    case AgentMessageType.SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
                        if (locked)
                            return Failure();
                        _keys.Clear();
                        return Success();
                    case AgentMessageType.SSH_AGENTC_LOCK:
                        return SetLock(reader, locking: true);
                    case AgentMessageType.SSH_AGENTC_UNLOCK:
                        return SetLock(reader, locking: false);
                    default:
                        return Failure();
                }
            }
        }

        private byte[] IdentitiesAnswer(bool locked)
        {
            using var stream = new MemoryStream();
            using var writer = new AgentWriter(stream);
            writer.Write((byte)AgentMessageType.SSH2_AGENT_IDENTITIES_ANSWER);

            // a locked agent hides its identities
            var keys = locked ? new List<IPrivateKeySource>() : _keys;
            writer.Write((uint)keys.Count);
            foreach (var key in keys)
            {
                writer.EncodeString(PublicBlob(key));
                writer.EncodeString(Comment(key));
            }
            return stream.ToArray();
        }

        private byte[] SignResponse(AgentReader reader)
        {
            var keyBlob = reader.ReadStringAsBytes();
            var data = reader.ReadStringAsBytes();
            var flags = reader.ReadUInt32();

            var algorithm = SelectForSigning(keyBlob, flags);
            if (algorithm is null)
                return Failure();

            using var stream = new MemoryStream();
            using var writer = new AgentWriter(stream);
            writer.Write((byte)AgentMessageType.SSH2_AGENT_SIGN_RESPONSE);
            writer.EncodeString(algorithm.Sign(data));
            return stream.ToArray();
        }

        private byte[] RemoveIdentity(AgentReader reader)
        {
            var keyBlob = reader.ReadStringAsBytes();
            var match = _keys.FirstOrDefault(key => PublicBlob(key).SequenceEqual(keyBlob));
            if (match is null)
                return Failure();
            _keys.Remove(match);
            return Success();
        }

        private byte[] SetLock(AgentReader reader, bool locking)
        {
            var passphrase = reader.ReadStringAsBytes();
            if (locking)
            {
                if (_lockPassphrase is not null)
                    return Failure(); // already locked
                _lockPassphrase = passphrase;
                return Success();
            }

            if (_lockPassphrase is null || !_lockPassphrase.SequenceEqual(passphrase))
                return Failure();
            _lockPassphrase = null;
            return Success();
        }

        /// <summary>Finds the key matching the requested blob and the algorithm to sign with.</summary>
        private HostAlgorithm? SelectForSigning(byte[] keyBlob, uint flags)
        {
            foreach (var key in _keys)
            {
                var matching = key.HostKeyAlgorithms.Where(a => a.Data.SequenceEqual(keyBlob)).ToList();
                if (matching.Count == 0)
                    continue;

                // RSA offers several signature algorithms over the same key blob;
                // the sign flags pick the hash (RFC 8332)
                string? preferred = null;
                if ((flags & RsaSha2_512) != 0)
                    preferred = "rsa-sha2-512";
                else if ((flags & RsaSha2_256) != 0)
                    preferred = "rsa-sha2-256";
                if (preferred is not null)
                {
                    var byFlag = matching.FirstOrDefault(a => a.Name.Contains(preferred));
                    if (byFlag is not null)
                        return byFlag;
                }
                return matching[0];
            }
            return null;
        }

        private static byte[] PublicBlob(IPrivateKeySource key)
        {
            return key.HostKeyAlgorithms.First().Data;
        }

        private static string Comment(IPrivateKeySource key)
        {
            // CertificateHostAlgorithm derives from KeyHostAlgorithm, so this
            // covers plain keys and certificates alike
            return key.HostKeyAlgorithms.First() is KeyHostAlgorithm keyAlgorithm
                ? keyAlgorithm.Key.Comment ?? ""
                : "";
        }

        private static byte[] Success() => new[] { (byte)AgentMessageType.SSH_AGENT_SUCCESS };
        private static byte[] Failure() => new[] { (byte)AgentMessageType.SSH_AGENT_FAILURE };

        private static byte[] Frame(byte[] payload)
        {
            var framed = new byte[4 + payload.Length];
            var length = (uint)payload.Length;
            framed[0] = (byte)(length >> 24);
            framed[1] = (byte)(length >> 16);
            framed[2] = (byte)(length >> 8);
            framed[3] = (byte)length;
            Buffer.BlockCopy(payload, 0, framed, 4, payload.Length);
            return framed;
        }

        private const int MaxMessageLength = 256 * 1024; // OpenSSH AGENT_MAX_MSGLEN

        private static async Task<byte[]?> ReadMessageAsync(Stream stream, CancellationToken token)
        {
            var header = await ReadExactlyAsync(stream, 4, token).ConfigureAwait(false);
            if (header is null)
                return null;
            var length = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
            if (length < 1 || length > MaxMessageLength)
                throw new InvalidDataException($"Invalid agent message length {length}");
            return await ReadExactlyAsync(stream, length, token).ConfigureAwait(false);
        }

        private static async Task<byte[]?> ReadExactlyAsync(Stream stream, int count, CancellationToken token)
        {
            var buffer = new byte[count];
            var offset = 0;
            while (offset < count)
            {
                var read = await stream.ReadAsync(buffer, offset, count - offset, token).ConfigureAwait(false);
                if (read == 0)
                    return null;
                offset += read;
            }
            return buffer;
        }

        /// <summary>Stops the server and releases the socket or pipe.</summary>
        public void Dispose()
        {
            _cts.Cancel();
            try
            {
                _listener?.Wait(TimeSpan.FromSeconds(5));
            }
            catch
            {
                // listener aborted on cancellation
            }
            _cts.Dispose();
#if NETSTANDARD2_1 || NET
            if (_socketFile is not null)
            {
                try { File.Delete(_socketFile); } catch { /* best effort */ }
            }
#endif
        }
    }
}

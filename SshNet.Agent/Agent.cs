using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Renci.SshNet;
using SshNet.Agent.AgentMessage;
using SshNet.Agent.Keys;

namespace SshNet.Agent
{
    public sealed class Agent : IDisposable
    {
        private readonly NamedPipeClientStream? _pipe;
        private readonly Socket? _socket;
        private readonly Stream _stream;
        private readonly AgentReader _reader;
        private readonly AgentWriter _writer;

        public Agent() : this(AgentSocketPath.GetPath())
        {
        }

        public Agent(string socketPath)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _pipe = new NamedPipeClientStream(".", socketPath, PipeDirection.InOut);
                _pipe.Connect();
                _stream = _pipe;
            }
            else
            {
                var ep = new UnixDomainSocketEndPoint(socketPath);
                _socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.IP);
                _socket.Connect(ep);
                _stream = new NetworkStream(_socket);
            }

            _reader = new AgentReader(_stream);
            _writer = new AgentWriter(_stream);
        }

        public IEnumerable<AgentIdentity> RequestIdentities()
        {
            return (IEnumerable<AgentIdentity>)Send(new RequestIdentities(this));
        }

        public void RemoveAllIdentities()
        {
            _ = Send(new RemoveIdentity(RemoveIdentityMode.All));
        }

        public void AddIdentity(PrivateKeyFile keyFile)
        {
            _ = Send(new AddIdentity(keyFile));
        }

        public byte[] Sign(AgentKey key, byte[] data)
        {
            return (byte[])Send(new RequestSign(key, data));
        }

        private object Send(IAgentMessage message)
        {
            message.To(_writer);
            return message.From(_reader);
        }

        #region IDisposable
        private bool _disposed;
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                _reader?.Dispose();
                _writer?.Dispose();
                _stream?.Dispose();
                _socket?.Dispose();
                _pipe?.Dispose();
            }

            _disposed = true;
        }
        #endregion
    }
}
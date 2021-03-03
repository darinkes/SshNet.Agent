using System;
using System.IO;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace SshNet.Agent
{
    public class AgentSocketStream : Stream, IDisposable
    {
        private readonly NamedPipeClientStream? _pipe;
        private readonly Socket? _socket;
        private readonly Stream _stream;

        public override void Flush()
        {
            _stream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _stream.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return _stream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            _stream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _stream.Write(buffer, offset, count);
        }

        public override bool CanRead => _stream.CanRead;
        public override bool CanSeek => _stream.CanSeek;
        public override bool CanWrite => _stream.CanWrite;
        public override long Length => _stream.Length;
        public override long Position
        {
            get => _stream.Position;
            set => _stream.Position = value;
        }

        public AgentSocketStream(string socketPath)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _pipe = new NamedPipeClientStream(".", socketPath, PipeDirection.InOut);
                _pipe.Connect();
                _stream = _pipe;
                return;
            }

            var ep = new UnixDomainSocketEndPoint(socketPath);
            _socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.IP);
            _socket.Connect(ep);
            _stream = new NetworkStream(_socket);
        }

        #region IDisposable
        private bool _disposed;
        public new void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private new void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                _stream?.Dispose();
                _socket?.Dispose();
                _pipe?.Dispose();
            }

            _disposed = true;
        }
        #endregion
    }
}
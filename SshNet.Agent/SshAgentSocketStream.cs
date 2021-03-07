using System;
using System.IO;
using System.IO.Pipes;
#if NETSTANDARD2_1
using System.Runtime.InteropServices;
using System.Net.Sockets;
#endif

namespace SshNet.Agent
{
    internal class SshAgentSocketStream : Stream, IDisposable
    {
        private readonly NamedPipeClientStream? _pipe;
        private readonly Stream _stream;
#if NETSTANDARD2_1
        private readonly Socket? _socket;
#endif

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

        public SshAgentSocketStream(string socketPath)
        {
#if NETSTANDARD2_1
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var ep = new UnixDomainSocketEndPoint(socketPath);
                _socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.IP);
                _socket.Connect(ep);
                _stream = new NetworkStream(_socket);
                return;
            }
#endif
            _pipe = new NamedPipeClientStream(".", socketPath, PipeDirection.InOut);
            _pipe.Connect();
            _stream = _pipe;
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
                _stream.Dispose();
#if NETSTANDARD2_1
                _socket?.Dispose();
#endif
                _pipe?.Dispose();
            }

            _disposed = true;
        }
        #endregion
    }
}
using System;
using System.IO;
using System.IO.Pipes;
using System.Threading.Tasks;
#if NETSTANDARD2_1
using System.Runtime.InteropServices;
using System.Net.Sockets;
#endif

namespace SshNet.Agent
{
    internal class SshAgentSocketStream : Stream, IDisposable
    {
        private const string PipePrefix = @"\\.\pipe\";

        private readonly NamedPipeClientStream? _pipe;
        private readonly Stream _stream;
        private readonly TimeSpan _timeout;
#if NETSTANDARD2_1
        private readonly Socket? _socket;
#endif

        public override void Flush()
        {
            _stream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_pipe is null)
                return _stream.Read(buffer, offset, count);

            // named pipes have no read/write timeouts, so enforce them ourselves;
            // without one a stalled agent blocks the caller forever
            var read = _stream.ReadAsync(buffer, offset, count);
            WaitWithTimeout(read);
            return read.Result;
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
            if (_pipe is null)
            {
                _stream.Write(buffer, offset, count);
                return;
            }

            WaitWithTimeout(_stream.WriteAsync(buffer, offset, count));
        }

        private void WaitWithTimeout(Task task)
        {
            // the pending operation is left to be aborted by Dispose, which the
            // owner runs when this exception unwinds its using statement
            if (Task.WaitAny(new Task[] { task }, _timeout) == -1)
                throw new TimeoutException($"The ssh-agent did not answer within {_timeout.TotalSeconds:0.#}s");
            task.GetAwaiter().GetResult(); // surfaces a fault unwrapped
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

        public SshAgentSocketStream(string socketPath, TimeSpan timeout)
        {
            _timeout = timeout;
#if NETSTANDARD2_1
            // everything on unix is a unix domain socket; on Windows only paths
            // that exist as files are (e.g. WSL sockets), never pipe paths
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ||
                (!IsPipePath(socketPath) && File.Exists(socketPath)))
            {
                var ep = new UnixDomainSocketEndPoint(socketPath);
                _socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.IP);
                _socket.ReceiveTimeout = Convert.ToInt32(timeout.TotalMilliseconds);
                _socket.SendTimeout = Convert.ToInt32(timeout.TotalMilliseconds);
                _socket.Connect(ep);
                _stream = new NetworkStream(_socket);
                return;
            }
#endif
            _pipe = new NamedPipeClientStream(".", PipeName(socketPath), PipeDirection.InOut, PipeOptions.Asynchronous);
            _pipe.Connect(Convert.ToInt32(timeout.TotalMilliseconds));
            _stream = _pipe;
        }

        private static bool IsPipePath(string socketPath)
        {
            return socketPath.StartsWith(PipePrefix, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// NamedPipeClientStream wants the bare pipe name, but SSH_AUTH_SOCK style
        /// configuration commonly holds the full path, e.g. \\.\pipe\openssh-ssh-agent.
        /// </summary>
        private static string PipeName(string socketPath)
        {
            return IsPipePath(socketPath) ? socketPath.Substring(PipePrefix.Length) : socketPath;
        }

        private bool _disposed;

        protected override void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _stream.Dispose();
#if NETSTANDARD2_1
                _socket?.Dispose();
#endif
                _pipe?.Dispose();
            }

            _disposed = true;
            base.Dispose(disposing);
        }
    }
}

using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
#if NETSTANDARD2_1 || NET
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
#if NETSTANDARD2_1 || NET
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

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            var read = _stream.ReadAsync(buffer, offset, count, cancellationToken);
            await WaitWithTimeoutAsync(read, cancellationToken).ConfigureAwait(false);
            return read.Result;
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await WaitWithTimeoutAsync(_stream.WriteAsync(buffer, offset, count, cancellationToken), cancellationToken).ConfigureAwait(false);
        }

        private async Task WaitWithTimeoutAsync(Task task, CancellationToken cancellationToken)
        {
            using var stopDelay = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var winner = await Task.WhenAny(task, Task.Delay(_timeout, stopDelay.Token)).ConfigureAwait(false);
            if (winner != task)
            {
                cancellationToken.ThrowIfCancellationRequested();
                // the pending operation is aborted by Dispose, run by the owner
                // when this exception unwinds its using statement
                throw new TimeoutException($"The ssh-agent did not answer within {_timeout.TotalSeconds:0.#}s");
            }
            stopDelay.Cancel();
            await task.ConfigureAwait(false);
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
#if NETSTANDARD2_1 || NET
            if (UseUnixSocket(socketPath))
            {
                var socket = CreateUnixSocket(timeout);
                try
                {
                    // sync Connect has no timeout of its own, so bound it here
                    var connect = socket.BeginConnect(new UnixDomainSocketEndPoint(socketPath), null, null);
                    if (!connect.AsyncWaitHandle.WaitOne(timeout))
                        throw new TimeoutException($"Could not connect to the ssh-agent within {timeout.TotalSeconds:0.#}s");
                    socket.EndConnect(connect);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
                _socket = socket;
                _stream = new NetworkStream(socket);
                return;
            }
#endif
            var pipe = CreatePipe(socketPath);
            try
            {
                pipe.Connect(Convert.ToInt32(timeout.TotalMilliseconds));
            }
            catch
            {
                pipe.Dispose();
                throw;
            }
            _pipe = pipe;
            _stream = pipe;
        }

#if NETSTANDARD2_1 || NET
        private SshAgentSocketStream(Socket socket, TimeSpan timeout)
        {
            _socket = socket;
            _stream = new NetworkStream(socket);
            _timeout = timeout;
        }
#endif

        private SshAgentSocketStream(NamedPipeClientStream pipe, TimeSpan timeout)
        {
            _pipe = pipe;
            _stream = pipe;
            _timeout = timeout;
        }

        public static async Task<SshAgentSocketStream> ConnectAsync(string socketPath, TimeSpan timeout, CancellationToken cancellationToken)
        {
#if NETSTANDARD2_1 || NET
            if (UseUnixSocket(socketPath))
            {
                var socket = CreateUnixSocket(timeout);
                try
                {
                    var connect = socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath));
                    if (await Task.WhenAny(connect, Task.Delay(timeout, cancellationToken)).ConfigureAwait(false) != connect)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        throw new TimeoutException($"Could not connect to the ssh-agent within {timeout.TotalSeconds:0.#}s");
                    }
                    await connect.ConfigureAwait(false);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
                return new SshAgentSocketStream(socket, timeout);
            }
#endif
            var pipe = CreatePipe(socketPath);
            try
            {
                await pipe.ConnectAsync(Convert.ToInt32(timeout.TotalMilliseconds), cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                pipe.Dispose();
                throw;
            }
            return new SshAgentSocketStream(pipe, timeout);
        }

#if NETSTANDARD2_1 || NET
        /// <summary>
        /// Everything on unix is a unix domain socket; on Windows only paths
        /// that exist as files are (e.g. WSL sockets), never pipe paths.
        /// </summary>
        private static bool UseUnixSocket(string socketPath)
        {
            return !RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ||
                   (!IsPipePath(socketPath) && File.Exists(socketPath));
        }

        private static Socket CreateUnixSocket(TimeSpan timeout)
        {
            var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.IP);
            socket.ReceiveTimeout = Convert.ToInt32(timeout.TotalMilliseconds);
            socket.SendTimeout = Convert.ToInt32(timeout.TotalMilliseconds);
            return socket;
        }
#endif

        private static NamedPipeClientStream CreatePipe(string socketPath)
        {
            return new NamedPipeClientStream(".", PipeName(socketPath), PipeDirection.InOut, PipeOptions.Asynchronous);
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
#if NETSTANDARD2_1 || NET
                _socket?.Dispose();
#endif
                _pipe?.Dispose();
            }

            _disposed = true;
            base.Dispose(disposing);
        }
    }
}

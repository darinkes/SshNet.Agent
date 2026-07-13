using System;
using System.Collections.Concurrent;
using System.IO;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SshNet.Agent.Tests
{
    /// <summary>
    /// A minimal in-process ssh-agent for protocol-level tests. It records every
    /// raw request and answers each one with the next canned response (or
    /// SSH_AGENT_FAILURE when none is queued). SshAgent opens a fresh connection
    /// per message, so the fake accepts one request per connection. Windows is
    /// served over a named pipe, everything else over a unix domain socket - the
    /// same transports the library uses.
    /// </summary>
    internal sealed class FakeAgent : IDisposable
    {
        private readonly CancellationTokenSource _cts = new();
        private readonly ConcurrentQueue<byte[]> _responses = new();
        private readonly Task _listener;
        private readonly string? _tempDir;

        /// <summary>Raw payloads (without the length prefix) of the recorded requests.</summary>
        public ConcurrentQueue<byte[]> Requests { get; } = new();

        /// <summary>The value to pass to the SshAgent constructor.</summary>
        public string SocketPath { get; }

        public FakeAgent()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                SocketPath = "sshnet-agent-fake-" + Guid.NewGuid().ToString("N");
                _listener = ListenPipeAsync(_cts.Token);
            }
            else
            {
                _tempDir = Directory.CreateTempSubdirectory("sshnet-agent-fake-").FullName;
                SocketPath = Path.Combine(_tempDir, "agent.sock");
                _listener = ListenSocketAsync(_cts.Token);
            }
        }

        public SshAgent CreateClient()
        {
            return new SshAgent(SocketPath, TimeSpan.FromSeconds(10));
        }

        /// <summary>Queues a response payload; the length prefix is added on send.</summary>
        public void EnqueueResponse(byte[] payload)
        {
            _responses.Enqueue(payload);
        }

        /// <summary>The payload of the single recorded request.</summary>
        public byte[] SingleRequest()
        {
            if (!Requests.TryDequeue(out var request))
                throw new InvalidOperationException("No request was recorded");
            if (!Requests.IsEmpty)
                throw new InvalidOperationException("More than one request was recorded");
            return request;
        }

        private async Task ListenPipeAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                using var server = new NamedPipeServerStream(SocketPath, PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                try
                {
                    await server.WaitForConnectionAsync(token).ConfigureAwait(false);
                    await HandleAsync(server, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (IOException)
                {
                    // client aborted, keep serving
                }
            }
        }

        private async Task ListenSocketAsync(CancellationToken token)
        {
            using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint(SocketPath));
            listener.Listen(5);
            using var abort = token.Register(() => listener.Dispose());
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
                try
                {
                    using var stream = new NetworkStream(client, ownsSocket: true);
                    await HandleAsync(stream, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (IOException)
                {
                    // client aborted, keep serving
                }
            }
        }

        private async Task HandleAsync(Stream stream, CancellationToken token)
        {
            var header = await ReadExactlyAsync(stream, 4, token).ConfigureAwait(false);
            if (header is null)
                return;
            var length = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
            var request = await ReadExactlyAsync(stream, length, token).ConfigureAwait(false);
            if (request is null)
                return;
            Requests.Enqueue(request);

            if (!_responses.TryDequeue(out var response))
                response = new byte[] { 5 }; // SSH_AGENT_FAILURE
            var message = Wire.Cat(Wire.U32((uint)response.Length), response);
            await stream.WriteAsync(message, 0, message.Length, token).ConfigureAwait(false);
            await stream.FlushAsync(token).ConfigureAwait(false);

            try
            {
                // wait for the client to close its end so no buffered data is lost
                await stream.ReadAsync(new byte[1], 0, 1, token).ConfigureAwait(false);
            }
            catch (IOException)
            {
                // client hung up
            }
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

        public void Dispose()
        {
            _cts.Cancel();
            try
            {
                _listener.Wait(TimeSpan.FromSeconds(5));
            }
            catch
            {
                // listener aborted
            }
            _cts.Dispose();
            if (_tempDir is not null)
            {
                try { Directory.Delete(_tempDir, recursive: true); } catch { /* best effort */ }
            }
        }
    }

    /// <summary>Builds ssh-agent wire format for the tests.</summary>
    internal static class Wire
    {
        public static byte[] U32(uint value)
        {
            return new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value };
        }

        public static byte[] Str(byte[] data)
        {
            return Cat(U32((uint)data.Length), data);
        }

        public static byte[] Str(string text)
        {
            return Str(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] Cat(params byte[][] parts)
        {
            var length = 0;
            foreach (var part in parts)
                length += part.Length;
            var result = new byte[length];
            var offset = 0;
            foreach (var part in parts)
            {
                Buffer.BlockCopy(part, 0, result, offset, part.Length);
                offset += part.Length;
            }
            return result;
        }
    }

    /// <summary>Reads ssh-agent wire format from a recorded request.</summary>
    internal sealed class WireReader
    {
        private readonly byte[] _data;
        private int _position;

        public WireReader(byte[] data)
        {
            _data = data;
        }

        public bool AtEnd => _position >= _data.Length;

        public byte Byte()
        {
            return _data[_position++];
        }

        public uint U32()
        {
            var value = ((uint)_data[_position] << 24) | ((uint)_data[_position + 1] << 16) |
                        ((uint)_data[_position + 2] << 8) | _data[_position + 3];
            _position += 4;
            return value;
        }

        public byte[] Str()
        {
            var length = (int)U32();
            var result = new byte[length];
            Buffer.BlockCopy(_data, _position, result, 0, length);
            _position += length;
            return result;
        }

        public string Text()
        {
            return Encoding.UTF8.GetString(Str());
        }
    }
}

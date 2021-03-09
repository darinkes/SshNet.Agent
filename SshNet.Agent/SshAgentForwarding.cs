#if NETSTANDARD2_1
using System;
using System.IO;
using System.Net.Sockets;
using Renci.SshNet;

namespace SshNet.Agent
{
    public class SshAgentForwarding
    {
        private readonly Socket _listener;
        private readonly SshAgent _sshAgent;

        public ForwardedPortRemote ForwardedPort { get; }
        public string RemotePath { get; }

        public SshAgentForwarding(SshAgent sshAgent, string remotePath = "")
        {
            _sshAgent = sshAgent;

            var localPath = Path.GetTempFileName();
            if (File.Exists(localPath))
                File.Delete(localPath);

            RemotePath = string.IsNullOrEmpty(remotePath)
                ? $"/tmp/test-agent-${Path.GetRandomFileName()}.sock"
                : remotePath;

            var localEndpoint = new UnixDomainSocketEndPoint(localPath);
            var remoteEndpoint = new UnixDomainSocketEndPoint(RemotePath);

            _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            _listener.Bind(localEndpoint);
            _listener.Listen(5);

            ForwardedPort = new ForwardedPortRemote(remoteEndpoint, localEndpoint);
        }

        public void Start()
        {
            StartAccept(null);
            ForwardedPort.Start();
        }

        public void Stop()
        {
            ForwardedPort.Stop();
        }

        private void StartAccept(SocketAsyncEventArgs e)
        {
            if (e == null)
            {
                e = new SocketAsyncEventArgs();
                e.Completed += AcceptCompleted;
            }
            else
            {
                // clear the socket as we're reusing the context object
                e.AcceptSocket = null;
            }

            if (!_listener.AcceptAsync(e))
            {
                AcceptCompleted(null, e);
            }
        }

        private void AcceptCompleted(object sender, SocketAsyncEventArgs e)
        {
            if (e.SocketError == SocketError.OperationAborted || e.SocketError == SocketError.NotSocket)
            {
                // server was stopped
                return;
            }

            // capture client socket
            var clientSocket = e.AcceptSocket;

            if (e.SocketError != SocketError.Success)
            {
                // accept new connection
                StartAccept(e);
                // dispose broken client socket
                CloseClientSocket(clientSocket);
                return;
            }

            // accept new connection
            StartAccept(e);
            // process connection
            ProcessAccept(clientSocket);
        }

        private void ProcessAccept(Socket clientSocket)
        {
            while (clientSocket.Connected)
            {
                var buffer = new byte[1024];
                var bytesRead = clientSocket.Receive(buffer);
                if (bytesRead == 0)
                    break;
                var reply = RelayData(buffer, bytesRead);
                clientSocket.Send(reply);
            }
        }

        private byte[] RelayData(byte[] data, int size)
        {
            using Stream socketStream =
                _sshAgent is Pageant ? new PageantSocketStream() : new SshAgentSocketStream(_sshAgent.SocketPath);
            using var writer = new AgentWriter(socketStream);
            using var reader = new AgentReader(socketStream);
            writer.Write(data, 0, size);

            if (socketStream is PageantSocketStream)
            {
                ((PageantSocketStream)socketStream).Send();
            }

            var msglen = reader.ReadUInt32();
            var reply = reader.ReadBytes((int)msglen);

            using var ms = new MemoryStream();
            using var msWriter = new AgentWriter(ms);
            msWriter.EncodeString(reply);
            return ms.ToArray();
        }

        private static void CloseClientSocket(Socket clientSocket)
        {
            if (clientSocket.Connected)
            {
                try
                {
                    clientSocket.Shutdown(SocketShutdown.Send);
                }
                catch (Exception)
                {
                    // ignore exception when client socket was already closed
                }
            }

            clientSocket.Dispose();
        }
    }
}
#endif
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class UnixSocketTransportTests
    {
        /// <summary>
        /// Socket.Connect has no timeout of its own; an agent socket whose
        /// backlog is full (e.g. a hung agent) used to block the sync caller
        /// forever.
        /// </summary>
        [Fact]
        public void FullBacklog_TimesOutOnSyncConnect()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Assert.Skip("a full unix socket backlog refuses instead of blocking on Windows");

            var tempDir = Directory.CreateTempSubdirectory("sshnet-agent-backlog-").FullName;
            var fillers = new List<Socket>();
            try
            {
                var path = Path.Combine(tempDir, "agent.sock");
                using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                listener.Bind(new UnixDomainSocketEndPoint(path));
                listener.Listen(0); // never accepts, so the backlog fills immediately
                for (var i = 0; i < 4; i++)
                {
                    var filler = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                    fillers.Add(filler);
                    var connect = filler.BeginConnect(new UnixDomainSocketEndPoint(path), null, null);
                    if (!connect.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(200)))
                        break; // this connect blocks: the backlog is full now
                }

                var agent = new SshAgent(path, TimeSpan.FromMilliseconds(500));

                Assert.Throws<TimeoutException>(() => agent.RequestIdentities());
            }
            finally
            {
                foreach (var filler in fillers)
                    filler.Dispose();
                try { Directory.Delete(tempDir, recursive: true); } catch { /* best effort */ }
            }
        }
    }
}

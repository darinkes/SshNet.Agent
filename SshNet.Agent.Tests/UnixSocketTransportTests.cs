using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class UnixSocketTransportTests
    {
        /// <summary>
        /// Socket.Connect has no timeout of its own; the sync path must fail
        /// promptly (and dispose the socket) instead of blocking when the agent
        /// endpoint cannot be reached.
        /// </summary>
        [Fact]
        public void DeadSocket_SyncConnectFailsFast()
        {
            var tempDir = Directory.CreateTempSubdirectory("sshnet-agent-connect-").FullName;
            try
            {
                // a regular file, so the unix-socket path is taken on every OS, but nothing listens
                var path = Path.Combine(tempDir, "agent.sock");
                File.WriteAllBytes(path, Array.Empty<byte>());

                var agent = new SshAgent(path, TimeSpan.FromSeconds(2));

                var sw = Stopwatch.StartNew();
                var ex = Record.Exception(() => agent.RequestIdentities());
                sw.Stop();

                Assert.NotNull(ex); // connecting to a dead socket fails
                Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"connect hung for {sw.Elapsed}");
            }
            finally
            {
                try { Directory.Delete(tempDir, recursive: true); } catch { /* best effort */ }
            }
        }
    }
}

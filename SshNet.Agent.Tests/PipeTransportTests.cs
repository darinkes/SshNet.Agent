using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class PipeTransportTests
    {
        private const byte Ssh2AgentIdentitiesAnswer = 12;

        private static void SkipUnlessWindows()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Assert.Skip("named pipes are Windows only");
        }

        /// <summary>
        /// SSH_AUTH_SOCK style configuration commonly holds the full pipe path.
        /// It used to be routed to a unix domain socket connect (File.Exists
        /// returns true for pipe paths), which failed.
        /// </summary>
        [Fact]
        public void FullPipePath_Connects()
        {
            SkipUnlessWindows();
            using var fake = new FakeAgent();
            fake.EnqueueResponse(Wire.Cat(new[] { Ssh2AgentIdentitiesAnswer }, Wire.U32(0)));

            var agent = new SshAgent(@"\\.\pipe\" + fake.SocketPath, null);

            Assert.Empty(agent.RequestIdentities());
        }

        /// <summary>
        /// Named pipes have no read timeout; an agent that accepts the request
        /// but never answers (e.g. waiting on a confirmation dialog nobody sees)
        /// used to block the caller forever.
        /// </summary>
        [Fact]
        public void UnresponsiveAgent_TimesOutOnRead()
        {
            SkipUnlessWindows();
            var pipeName = "sshnet-agent-silent-" + Guid.NewGuid().ToString("N");
            // buffered, so the request can be written; the answer never comes
            using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous, inBufferSize: 4096, outBufferSize: 4096);
            _ = server.WaitForConnectionAsync(TestContext.Current.CancellationToken);
            var agent = new SshAgent(pipeName, TimeSpan.FromMilliseconds(500));

            Assert.Throws<TimeoutException>(() => agent.RequestIdentities());
        }

        /// <summary>
        /// Writes can stall as well: with no buffer space a pipe write blocks
        /// until the other side reads.
        /// </summary>
        [Fact]
        public void AgentThatStopsReading_TimesOutOnWrite()
        {
            SkipUnlessWindows();
            var pipeName = "sshnet-agent-stalled-" + Guid.NewGuid().ToString("N");
            // unbuffered and never read from, so any write blocks
            using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            _ = server.WaitForConnectionAsync(TestContext.Current.CancellationToken);
            var agent = new SshAgent(pipeName, TimeSpan.FromMilliseconds(500));

            Assert.Throws<TimeoutException>(() => agent.RequestIdentities());
        }
    }
}

using System;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Renci.SshNet;
using Renci.SshNet.Security;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class AsyncApiTests
    {
        private const byte Ssh2AgentIdentitiesAnswer = 12;
        private const byte Ssh2AgentcAddIdentity = 17;
        private const byte SshAgentSuccess = 6;

        [Fact]
        public async Task RequestIdentitiesAsync_ReturnsTheIdentities()
        {
            using var fake = new FakeAgent();
            var blob = TestKeys.PublicKeyBlob(TestKeys.Ed25519Puttygen);
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentIdentitiesAnswer },
                Wire.U32(1),
                Wire.Str(blob), Wire.Str("ed25519 key")));

            var identities = await fake.CreateClient().RequestIdentitiesAsync(TestContext.Current.CancellationToken);

            var identity = Assert.Single(identities);
            var algorithm = (KeyHostAlgorithm)identity.HostKeyAlgorithms.First();
            Assert.Equal(blob, algorithm.Data);
            Assert.Equal("ed25519 key", algorithm.Key.Comment);
        }

        [Fact]
        public async Task AddIdentityAsync_SendsTheSameMessageAsTheSyncApi()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });
            var keyFile = new PrivateKeyFile(TestKeys.PrivateKeyPath(TestKeys.Ed25519Puttygen));

            await fake.CreateClient().AddIdentityAsync(keyFile, TestContext.Current.CancellationToken);

            var request = new WireReader(fake.SingleRequest());
            Assert.Equal(Ssh2AgentcAddIdentity, request.Byte());
            Assert.Equal("ssh-ed25519", request.Text());
        }

        [Fact]
        public async Task RemoveAllIdentitiesAsync_Succeeds()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });

            await fake.CreateClient().RemoveAllIdentitiesAsync(TestContext.Current.CancellationToken);

            var request = new WireReader(fake.SingleRequest());
            Assert.Equal(19, request.Byte()); // SSH2_AGENTC_REMOVE_ALL_IDENTITIES
        }

        [Fact]
        public async Task UnresponsiveAgent_TimesOutAsync()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Assert.Skip("named pipes are Windows only");

            var pipeName = "sshnet-agent-silent-" + Guid.NewGuid().ToString("N");
            // buffered, so the request can be written; the answer never comes
            using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous, inBufferSize: 4096, outBufferSize: 4096);
            _ = server.WaitForConnectionAsync();
            var agent = new SshAgent(pipeName, TimeSpan.FromMilliseconds(500));

            await Assert.ThrowsAsync<TimeoutException>(
                () => agent.RequestIdentitiesAsync(TestContext.Current.CancellationToken));
        }

        [Fact]
        public async Task CanceledToken_CancelsTheRequest()
        {
            using var fake = new FakeAgent();
            using var canceled = new CancellationTokenSource();
            canceled.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => fake.CreateClient().RequestIdentitiesAsync(canceled.Token));
        }
    }
}

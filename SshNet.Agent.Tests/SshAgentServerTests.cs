using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Security;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class SshAgentServerTests : IClassFixture<SshServerFixture>
    {
        private readonly SshServerFixture _server;

        public SshAgentServerTests(SshServerFixture server)
        {
            _server = server;
        }

        /// <summary>Starts the server on a fresh endpoint and returns a client for it.</summary>
        private static SshAgent StartClient(SshAgentServer server, out string? tempDir)
        {
            string endpoint;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                tempDir = null;
                endpoint = "sshnet-agent-server-" + Guid.NewGuid().ToString("N");
            }
            else
            {
                tempDir = Directory.CreateTempSubdirectory("sshnet-agent-server-").FullName;
                endpoint = Path.Combine(tempDir, "agent.sock");
            }
            server.Start(endpoint);
            return new SshAgent(endpoint, TimeSpan.FromSeconds(10));
        }

        private static void Cleanup(string? tempDir)
        {
            if (tempDir is not null)
            {
                try { Directory.Delete(tempDir, recursive: true); } catch { /* best effort */ }
            }
        }

        [Fact]
        public void ListsIdentities_WithBlobAndComment()
        {
            var keyFile = TestKeys.PrivateKey(TestKeys.Ed25519Puttygen);
            using var server = new SshAgentServer(keyFile);
            var client = StartClient(server, out var tempDir);
            try
            {
                var identity = Assert.Single(client.RequestIdentities());
                Assert.Equal("sshnet-agent-test-" + TestKeys.Ed25519Puttygen, identity.Comment);
                Assert.Equal(TestKeys.PublicKeyBlob(TestKeys.Ed25519Puttygen),
                    ((KeyHostAlgorithm)identity.HostKeyAlgorithms.First()).Data);
            }
            finally
            {
                Cleanup(tempDir);
            }
        }

        [Theory]
        [InlineData(TestKeys.Rsa)]
        [InlineData(TestKeys.Ecdsa)]
        [InlineData(TestKeys.Ed25519Puttygen)]
        public void SignsData_ThatVerifiesAgainstThePublicKey(string keyName)
        {
            var keyFile = TestKeys.PrivateKey(keyName);
            using var server = new SshAgentServer(keyFile);
            var client = StartClient(server, out var tempDir);
            try
            {
                var identity = Assert.Single(client.RequestIdentities());
                var data = Encoding.UTF8.GetBytes("the quick brown fox");

                // signing round-trips to the server, which signs with the in-process key
                var signAlgorithm = (KeyHostAlgorithm)identity.HostKeyAlgorithms.First();
                var signature = signAlgorithm.Sign(data);

                var verifier = keyFile.HostKeyAlgorithms.OfType<KeyHostAlgorithm>()
                    .First(algorithm => algorithm.Name == signAlgorithm.Name);
                Assert.True(verifier.VerifySignature(data, signature));
            }
            finally
            {
                Cleanup(tempDir);
            }
        }

        [Fact]
        public void Locked_HidesIdentities_UntilUnlocked()
        {
            using var server = new SshAgentServer(TestKeys.PrivateKey(TestKeys.Ed25519Puttygen));
            var client = StartClient(server, out var tempDir);
            try
            {
                Assert.Single(client.RequestIdentities());

                client.Lock("passphrase");
                Assert.Empty(client.RequestIdentities());

                client.Unlock("passphrase");
                Assert.Single(client.RequestIdentities());
            }
            finally
            {
                Cleanup(tempDir);
            }
        }

        [Fact]
        public void Unlock_WithTheWrongPassphrase_Throws()
        {
            using var server = new SshAgentServer(TestKeys.PrivateKey(TestKeys.Ed25519Puttygen));
            var client = StartClient(server, out var tempDir);
            try
            {
                client.Lock("passphrase");
                Assert.Throws<SshAgentFailureException>(() => client.Unlock("wrong"));
            }
            finally
            {
                Cleanup(tempDir);
            }
        }

        [Fact]
        public void RemoveIdentity_DropsTheKey()
        {
            using var server = new SshAgentServer(TestKeys.PrivateKey(TestKeys.Ed25519Puttygen));
            var client = StartClient(server, out var tempDir);
            try
            {
                var identity = Assert.Single(client.RequestIdentities());
                client.RemoveIdentity(identity);
                Assert.Empty(client.RequestIdentities());
            }
            finally
            {
                Cleanup(tempDir);
            }
        }

        [Fact]
        public void ServedKey_AuthenticatesAgainstARealServer()
        {
            _server.SkipUnlessAvailable();
            using var agentServer = new SshAgentServer(TestKeys.PrivateKey(TestKeys.Ed25519Puttygen));
            var client = StartClient(agentServer, out var tempDir);
            try
            {
                var keys = client.RequestIdentities();
                using var ssh = new SshClient(new ConnectionInfo(_server.Host, _server.Port, _server.User,
                    new PrivateKeyAuthenticationMethod(_server.User, keys.ToArray<IPrivateKeySource>())));
                ssh.Connect();
                Assert.Equal("ok", ssh.RunCommand("echo ok").Result.Trim());
            }
            finally
            {
                Cleanup(tempDir);
            }
        }

        [Fact]
        public void RemoveAllIdentities_ClearsTheStore()
        {
            var server = new SshAgentServer(
                TestKeys.PrivateKey(TestKeys.Ed25519Puttygen),
                TestKeys.PrivateKey(TestKeys.Rsa));
            using (server)
            {
                var client = StartClient(server, out var tempDir);
                try
                {
                    Assert.Equal(2, client.RequestIdentities().Length);
                    client.RemoveAllIdentities();
                    Assert.Empty(client.RequestIdentities());
                }
                finally
                {
                    Cleanup(tempDir);
                }
            }
        }
    }
}

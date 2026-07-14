using System;
using System.IO;
using System.Threading;
using Renci.SshNet;
using Xunit;

namespace SshNet.Agent.Tests
{
    /// <summary>
    /// Real-world tests: keys served by a real agent (OpenSSH ssh-agent or PuTTY
    /// Pageant) are used to authenticate against a real OpenSSH server. Tests skip
    /// when the agent kind or the server is not available on this machine.
    /// </summary>
    public class RealWorldTests : IClassFixture<SshServerFixture>
    {
        private readonly SshServerFixture _server;

        public RealWorldTests(SshServerFixture server)
        {
            _server = server;
        }

        private string Login(params IPrivateKeySource[] keys)
        {
            using var client = new SshClient(new ConnectionInfo(_server.Host, _server.Port, _server.User,
                new PrivateKeyAuthenticationMethod(_server.User, keys)));
            client.Connect();
            return client.RunCommand("echo ok").Result.Trim();
        }

        [Theory]
        [InlineData(AgentKind.OpenSsh)]
        [InlineData(AgentKind.Pageant)]
        public void Ed25519KeyFromPuttygen_Authenticates(AgentKind kind)
        {
            _server.SkipUnlessAvailable();
            using var agent = TestAgent.Start(kind, TestKeys.Ed25519Puttygen);

            Assert.Equal("ok", Login(agent.Identity(TestKeys.Ed25519Puttygen)));
        }

        [Theory]
        [InlineData(AgentKind.OpenSsh)]
        [InlineData(AgentKind.Pageant)]
        public void Ed25519KeyWithLeadingZeroPublicKey_Authenticates(AgentKind kind)
        {
            _server.SkipUnlessAvailable();
            using var agent = TestAgent.Start(kind, TestKeys.Ed25519ZeroLead);

            Assert.Equal("ok", Login(agent.Identity(TestKeys.Ed25519ZeroLead)));
        }

        /// <summary>
        /// A key added with a lifetime (ssh-add -t) disappears from the agent by
        /// itself. Needs no SSH server. Skips when the agent refuses constrained
        /// adds or does not enforce the lifetime, since support varies by agent.
        /// </summary>
        [Theory]
        [InlineData(AgentKind.OpenSsh)]
        [InlineData(AgentKind.Pageant)]
        public void KeyWithLifetime_ExpiresFromTheAgent(AgentKind kind)
        {
            using var testAgent = TestAgent.Start(kind);
            var agent = testAgent.Agent;

            try
            {
                agent.AddIdentity(TestKeys.PrivateKey(TestKeys.Ed25519Puttygen), TimeSpan.FromSeconds(2));
            }
            catch (SshAgentFailureException)
            {
                Assert.Skip("the agent does not support key constraints");
            }
            Assert.NotNull(TestKeys.Find(agent.RequestIdentities(), TestKeys.Ed25519Puttygen));

            for (var i = 0; i < 50 && TestKeys.Find(agent.RequestIdentities(), TestKeys.Ed25519Puttygen) is not null; i++)
                Thread.Sleep(200);

            if (TestKeys.Find(agent.RequestIdentities(), TestKeys.Ed25519Puttygen) is not null)
                Assert.Skip("the agent accepted the lifetime constraint but does not enforce it");
        }

        [Theory]
        [InlineData(AgentKind.OpenSsh)]
        [InlineData(AgentKind.Pageant)]
        public void RsaKey_Authenticates(AgentKind kind)
        {
            _server.SkipUnlessAvailable();
            using var agent = TestAgent.Start(kind, TestKeys.Rsa);

            Assert.Equal("ok", Login(agent.Identity(TestKeys.Rsa)));
        }

        /// <summary>
        /// A locked agent hides its identities until it is unlocked again
        /// (ssh-add -x / -X). Needs no SSH server. Skips when the agent does not
        /// support locking. The agent is always unlocked again, even on failure,
        /// so a shared agent (e.g. the Windows service) is never left locked.
        /// </summary>
        [Theory]
        [InlineData(AgentKind.OpenSsh)]
        [InlineData(AgentKind.Pageant)]
        public void LockedAgent_HidesIdentitiesUntilUnlocked(AgentKind kind)
        {
            using var testAgent = TestAgent.Start(kind, TestKeys.Ed25519Puttygen);
            var agent = testAgent.Agent;
            Assert.NotNull(TestKeys.Find(agent.RequestIdentities(), TestKeys.Ed25519Puttygen));

            try
            {
                agent.Lock("correct horse battery staple");
            }
            catch (Exception e) when (e is SshAgentFailureException or EndOfStreamException)
            {
                // Pageant answers SSH_AGENT_FAILURE, the Windows OpenSSH agent
                // just closes the connection without answering
                Assert.Skip($"the agent does not support locking ({e.Message})");
            }

            try
            {
                Assert.Null(TestKeys.Find(agent.RequestIdentities(), TestKeys.Ed25519Puttygen));
            }
            finally
            {
                agent.Unlock("correct horse battery staple");
            }

            Assert.NotNull(TestKeys.Find(agent.RequestIdentities(), TestKeys.Ed25519Puttygen));
        }

        [Theory]
        [InlineData(AgentKind.OpenSsh)]
        [InlineData(AgentKind.Pageant)]
        public void EcdsaKey_Authenticates(AgentKind kind)
        {
            _server.SkipUnlessAvailable();
            using var agent = TestAgent.Start(kind, TestKeys.Ecdsa);

            Assert.Equal("ok", Login(agent.Identity(TestKeys.Ecdsa)));
        }

        /// <summary>
        /// An OpenSSH certificate as the agent identity: the certificate and the
        /// private key are added to a real agent, the server trusts only the CA
        /// (TrustedUserCAKeys), not the key itself.
        /// </summary>
        [Theory]
        [InlineData(AgentKind.OpenSsh)]
        [InlineData(AgentKind.Pageant)]
        public void CertificateIdentity_Authenticates(AgentKind kind)
        {
            _server.SkipUnlessAvailable();
            _server.SkipUnlessTrustsTestCa();
            using var agent = StartWithCertificate(kind);

            Assert.Equal("ok", Login(agent.Identity(TestKeys.Ed25519Cert)));
        }

        private static TestAgent StartWithCertificate(AgentKind kind)
        {
            try
            {
                return TestAgent.Start(kind, TestKeys.Ed25519Cert);
            }
            catch (Exception e) when (e is SshAgentFailureException or EndOfStreamException)
            {
                // certificate support varies by agent, like constraints and locking
                Assert.Skip($"the agent does not support certificate identities ({e.Message})");
                throw; // unreachable, Assert.Skip does not return
            }
        }

        /// <summary>
        /// Regression test for GitHub issue #13: the authorized ed25519 key sits
        /// behind two RSA keys the server does not accept. Every offered host key
        /// algorithm costs one of the server's MaxAuthTries (default 6), and each
        /// RSA key used to be offered with three algorithms (legacy ssh-rsa first,
        /// which OpenSSH 8.8+ rejects outright), so the server disconnected with
        /// "Too many authentication failures" before the ed25519 key was tried.
        /// </summary>
        [Theory]
        [InlineData(AgentKind.OpenSsh)]
        [InlineData(AgentKind.Pageant)]
        public void Ed25519KeyBehindUnauthorizedRsaKeys_Authenticates(AgentKind kind)
        {
            _server.SkipUnlessAvailable();
            using var agent = TestAgent.Start(kind,
                TestKeys.RsaUnauthorizedB, TestKeys.RsaUnauthorizedC, TestKeys.Ed25519Puttygen);

            Assert.Equal("ok", Login(
                agent.Identity(TestKeys.RsaUnauthorizedB),
                agent.Identity(TestKeys.RsaUnauthorizedC),
                agent.Identity(TestKeys.Ed25519Puttygen)));
        }
    }
}

using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Containers;
using Xunit;

namespace SshNet.Agent.Tests
{
    /// <summary>
    /// A real OpenSSH server for the tests to authenticate against, accepting only
    /// the TestKeys.Authorized keys. Uses the server from
    /// SSHNET_AGENT_SERVER=host:port:user when set (native sshd on the Windows CI
    /// runner), otherwise starts a Docker container.
    /// </summary>
    public sealed class SshServerFixture : IAsyncLifetime
    {
        private IContainer? _container;

        public string Host { get; private set; } = "";
        public int Port { get; private set; }
        public string User { get; private set; } = "";
        public string SkipReason { get; private set; } = "";

        /// <summary>
        /// Whether the server trusts certificates signed by the test CA. Only
        /// the container is configured for it; an external server via
        /// SSHNET_AGENT_SERVER is not.
        /// </summary>
        public bool TrustsTestCa { get; private set; }

        public async ValueTask InitializeAsync()
        {
            var external = Environment.GetEnvironmentVariable("SSHNET_AGENT_SERVER");
            if (!string.IsNullOrEmpty(external))
            {
                var parts = external.Split(':');
                Host = parts[0];
                Port = int.Parse(parts[1]);
                User = parts[2];
                return;
            }

            try
            {
                // the init script runs before sshd starts and makes it accept
                // certificates signed by the test CA (principal "test")
                var trustCa = "#!/bin/bash\necho \"TrustedUserCAKeys /ca/test_ca.pub\" >> /config/sshd/sshd_config\n";
                var builder = new ContainerBuilder("lscr.io/linuxserver/openssh-server:latest")
                    .WithEnvironment("USER_NAME", "test")
                    .WithEnvironment("PUBLIC_KEY_DIR", "/authorized")
                    .WithResourceMapping(new FileInfo(Path.Combine(TestKeys.Dir, "test_ca.pub")), "/ca/")
                    .WithResourceMapping(Encoding.ASCII.GetBytes(trustCa), "/custom-cont-init.d/20-trust-test-ca", fileMode: Unix.FileMode755)
                    .WithPortBinding(2222, assignRandomHostPort: true)
                    .WithWaitStrategy(Wait.ForUnixContainer().UntilMessageIsLogged(@"ls\.io-init\] done"));
                foreach (var name in TestKeys.Authorized)
                    builder = builder.WithResourceMapping(new FileInfo(TestKeys.PublicKeyPath(name)), "/authorized/");

                _container = builder.Build();
                await _container.StartAsync();
                Host = "127.0.0.1";
                Port = _container.GetMappedPublicPort(2222);
                User = "test";
                TrustsTestCa = true;
            }
            catch (Exception e)
            {
                SkipReason = $"no SSH server available, set SSHNET_AGENT_SERVER or start Docker ({e.Message})";
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_container is not null)
                await _container.DisposeAsync();
        }

        public void SkipUnlessAvailable()
        {
            if (Host.Length == 0)
                TestEnvironment.Unavailable("Server", SkipReason);
        }

        public void SkipUnlessTrustsTestCa()
        {
            if (!TrustsTestCa)
                Assert.Skip("the server is not configured to trust the test CA");
        }
    }
}

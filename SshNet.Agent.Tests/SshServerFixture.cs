using System;
using System.IO;
using System.Threading.Tasks;
using DotNet.Testcontainers.Builders;
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
                var builder = new ContainerBuilder("lscr.io/linuxserver/openssh-server:latest")
                    .WithEnvironment("USER_NAME", "test")
                    .WithEnvironment("PUBLIC_KEY_DIR", "/authorized")
                    .WithPortBinding(2222, assignRandomHostPort: true)
                    .WithWaitStrategy(Wait.ForUnixContainer().UntilMessageIsLogged(@"ls\.io-init\] done"));
                foreach (var name in TestKeys.Authorized)
                    builder = builder.WithResourceMapping(new FileInfo(TestKeys.PublicKeyPath(name)), "/authorized/");

                _container = builder.Build();
                await _container.StartAsync();
                Host = "127.0.0.1";
                Port = _container.GetMappedPublicPort(2222);
                User = "test";
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
    }
}

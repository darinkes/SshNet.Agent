using System.Runtime.InteropServices;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class PageantPipeSelectionTests
    {
        [Fact]
        public void WithoutNamedPipe_UsesCopyDataTransport()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Assert.Skip("Pageant is Windows only");

            Assert.False(new Pageant((string?)null, null).UsesNamedPipe);
        }

        [Fact]
        public void PrefersPipeMatchingCurrentUser()
        {
            var names = new[] { "pageant.alice.aaaa", "pageant.bob.bbbb" };

            Assert.Equal("pageant.bob.bbbb", Pageant.SelectPipe(names, "bob"));
        }

        [Fact]
        public void FallsBackToFirstWhenNoUserMatch()
        {
            var names = new[] { "pageant.alice.aaaa", "pageant.carol.cccc" };

            Assert.Equal("pageant.alice.aaaa", Pageant.SelectPipe(names, "bob"));
        }

        [Fact]
        public void IgnoresNonPageantAndNullEntries()
        {
            var names = new[] { null, "openssh-ssh-agent", "pageant.bob.bbbb" };

            Assert.Equal("pageant.bob.bbbb", Pageant.SelectPipe(names, "bob"));
        }

        [Fact]
        public void ReturnsNullWhenNoPageantPipe()
        {
            var names = new[] { "openssh-ssh-agent", "docker_engine" };

            Assert.Null(Pageant.SelectPipe(names, "bob"));
        }
    }
}

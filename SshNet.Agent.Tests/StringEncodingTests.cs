using System.Linq;
using Renci.SshNet;
using Renci.SshNet.Security;
using Xunit;

namespace SshNet.Agent.Tests
{
    /// <summary>
    /// Key comments must survive the round trip through the agent as UTF-8, the
    /// encoding OpenSSH uses. The writer used to encode them as ASCII and the
    /// reader decoded them with the platform default (ANSI on .NET Framework).
    /// </summary>
    public class StringEncodingTests
    {
        private const string Comment = "grüße from München";
        private const byte Ssh2AgentIdentitiesAnswer = 12;
        private const byte SshAgentSuccess = 6;

        [Fact]
        public void AddIdentity_WritesTheCommentAsUtf8()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });
            var keyFile = new PrivateKeyFile(TestKeys.PrivateKeyPath(TestKeys.Ed25519Puttygen));
            ((KeyHostAlgorithm)keyFile.HostKeyAlgorithms.First()).Key.Comment = Comment;

            fake.CreateClient().AddIdentity(keyFile);

            var request = new WireReader(fake.SingleRequest());
            Assert.Equal(17, request.Byte()); // SSH2_AGENTC_ADD_IDENTITY
            Assert.Equal("ssh-ed25519", request.Text());
            request.Str(); // public key
            request.Str(); // private key
            Assert.Equal(Comment, request.Text());
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void RequestIdentities_ReadsTheCommentAsUtf8()
        {
            using var fake = new FakeAgent();
            var blob = TestKeys.PublicKeyBlob(TestKeys.Ed25519Puttygen);
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentIdentitiesAnswer },
                Wire.U32(1),
                Wire.Str(blob), Wire.Str(Comment)));

            var identity = Assert.Single(fake.CreateClient().RequestIdentities());

            Assert.Equal(Comment, ((KeyHostAlgorithm)identity.HostKeyAlgorithms.First()).Key.Comment);
        }
    }
}

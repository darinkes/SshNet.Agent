using System.Linq;
using Renci.SshNet.Security;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class RequestIdentitiesTests
    {
        private const byte Ssh2AgentIdentitiesAnswer = 12;

        [Fact]
        public void UnsupportedKeyTypes_AreSkipped()
        {
            using var fake = new FakeAgent();
            var ed25519Blob = TestKeys.PublicKeyBlob(TestKeys.Ed25519Puttygen);
            // a FIDO key as held by any agent that served ssh-keygen -t ed25519-sk
            var skBlob = Wire.Cat(
                Wire.Str("sk-ssh-ed25519@openssh.com"),
                Wire.Str(new byte[32]),
                Wire.Str("ssh:"));
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentIdentitiesAnswer },
                Wire.U32(2),
                Wire.Str(skBlob), Wire.Str("fido key"),
                Wire.Str(ed25519Blob), Wire.Str("ed25519 key")));

            var identities = fake.CreateClient().RequestIdentities();

            var identity = Assert.Single(identities);
            var algorithm = (KeyHostAlgorithm)identity.HostKeyAlgorithms.First();
            Assert.Equal(ed25519Blob, algorithm.Data);
            Assert.Equal("ed25519 key", algorithm.Key.Comment);
        }

        [Fact]
        public void EmptyAnswer_ReturnsNoIdentities()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(Wire.Cat(new[] { Ssh2AgentIdentitiesAnswer }, Wire.U32(0)));

            Assert.Empty(fake.CreateClient().RequestIdentities());
        }
    }
}

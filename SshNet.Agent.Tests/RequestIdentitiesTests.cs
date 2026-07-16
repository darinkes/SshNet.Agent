using System.IO;
using System.Linq;
using Renci.SshNet.Security;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class RequestIdentitiesTests
    {
        private const byte Ssh2AgentIdentitiesAnswer = 12;

        [Fact]
        public void FidoKey_IsOfferedWithItsBlobAndName()
        {
            using var fake = new FakeAgent();
            // a FIDO key as held by any agent that served ssh-keygen -t ed25519-sk
            var skBlob = Wire.Cat(
                Wire.Str("sk-ssh-ed25519@openssh.com"),
                Wire.Str(new byte[32]),
                Wire.Str("ssh:"));
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentIdentitiesAnswer },
                Wire.U32(1),
                Wire.Str(skBlob), Wire.Str("fido key")));

            var identity = Assert.Single(fake.CreateClient().RequestIdentities());

            var algorithm = identity.HostKeyAlgorithms.First();
            Assert.Equal("sk-ssh-ed25519@openssh.com", algorithm.Name);
            Assert.Equal(skBlob, algorithm.Data);
            Assert.Null(identity.Key); // no SSH.NET Key type for sk-* keys
            Assert.Equal("fido key", identity.Comment); // ... but the comment is still surfaced
        }

        [Fact]
        public void UnknownKeyTypes_AreSkipped()
        {
            using var fake = new FakeAgent();
            var ed25519Blob = TestKeys.PublicKeyBlob(TestKeys.Ed25519Puttygen);
            var unknownBlob = Wire.Cat(Wire.Str("ssh-something-new@openssh.com"), Wire.Str(new byte[8]));
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentIdentitiesAnswer },
                Wire.U32(2),
                Wire.Str(unknownBlob), Wire.Str("mystery key"),
                Wire.Str(ed25519Blob), Wire.Str("ed25519 key")));

            var identities = fake.CreateClient().RequestIdentities();

            var identity = Assert.Single(identities);
            var algorithm = (KeyHostAlgorithm)identity.HostKeyAlgorithms.First();
            Assert.Equal(ed25519Blob, algorithm.Data);
            Assert.Equal("ed25519 key", algorithm.Key!.Comment);
            Assert.Equal("ed25519 key", identity.Comment);
        }

        [Fact]
        public void EmptyAnswer_ReturnsNoIdentities()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(Wire.Cat(new[] { Ssh2AgentIdentitiesAnswer }, Wire.U32(0)));

            Assert.Empty(fake.CreateClient().RequestIdentities());
        }

        [Fact]
        public void OversizedResponse_IsRejected()
        {
            using var fake = new FakeAgent();
            // a length prefix beyond OpenSSH's AGENT_MAX_MSGLEN (256 KiB) must be refused,
            // not blindly allocated
            fake.EnqueueResponse(new byte[256 * 1024 + 1]);

            Assert.Throws<InvalidDataException>(() => fake.CreateClient().RequestIdentities());
        }
    }
}

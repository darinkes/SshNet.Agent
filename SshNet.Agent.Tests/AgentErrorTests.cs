using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using Renci.SshNet;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class AgentErrorTests
    {
        private const byte Ssh2AgentIdentitiesAnswer = 12;

        [Fact]
        public void AddIdentity_WhenTheAgentRefuses_ThrowsSshAgentFailureException()
        {
            // an unconfigured FakeAgent answers everything with SSH_AGENT_FAILURE
            using var fake = new FakeAgent();
            var keyFile = new PrivateKeyFile(TestKeys.PrivateKeyPath(TestKeys.Ed25519Puttygen));

            var exception = Assert.Throws<SshAgentFailureException>(() => fake.CreateClient().AddIdentity(keyFile));

            Assert.IsAssignableFrom<SshAgentException>(exception);
        }

        [Fact]
        public void Sign_WhenTheAgentRefuses_ThrowsSshAgentFailureException()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentIdentitiesAnswer },
                Wire.U32(1),
                Wire.Str(TestKeys.PublicKeyBlob(TestKeys.Ed25519Puttygen)), Wire.Str("key")));
            var identity = Assert.Single(fake.CreateClient().RequestIdentities());
            var algorithm = (KeyHostAlgorithm)identity.HostKeyAlgorithms.First();

            // the sign request is not answered with SSH2_AGENT_SIGN_RESPONSE
            Assert.Throws<SshAgentFailureException>(() => algorithm.Sign(new byte[] { 1, 2, 3 }));
        }

        [Fact]
        public void HugeClaimedStringLength_ThrowsInvalidDataException()
        {
            using var fake = new FakeAgent();
            // one identity whose key blob claims ~4 GB but carries no data
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentIdentitiesAnswer },
                Wire.U32(1),
                Wire.U32(0xfffffff0u)));

            Assert.Throws<InvalidDataException>(() => fake.CreateClient().RequestIdentities());
        }

        [Fact]
        public void AddIdentity_WithAnUnsupportedKeyType_ThrowsNotSupportedException()
        {
            using var fake = new FakeAgent();

            var exception = Assert.Throws<NotSupportedException>(
                () => fake.CreateClient().AddIdentity(new UnsupportedKeySource()));

            Assert.Contains("ssh-dss", exception.Message);
            // the malformed message was never sent
            Assert.True(fake.Requests.IsEmpty);
        }

        private sealed class StubSignature : DigitalSignature
        {
            public override bool Verify(byte[] input, byte[] signature) => false;

            public override byte[] Sign(byte[] input) => Array.Empty<byte>();
        }

        private sealed class UnsupportedKey : Key
        {
            protected override DigitalSignature DigitalSignature { get; } = new StubSignature();

            public override BigInteger[] Public => Array.Empty<BigInteger>();

            public override int KeyLength => 0;

            public override string ToString() => "ssh-dss";
        }

        private sealed class UnsupportedKeySource : IPrivateKeySource
        {
            private readonly Key _key = new UnsupportedKey();

            public IReadOnlyCollection<HostAlgorithm> HostKeyAlgorithms =>
                new HostAlgorithm[] { new KeyHostAlgorithm("ssh-dss", _key) };

            public Key Key => _key;
        }
    }
}

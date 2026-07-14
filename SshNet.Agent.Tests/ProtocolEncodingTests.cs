using System;
using System.Linq;
using System.Numerics;
using Renci.SshNet;
using Renci.SshNet.Security;
using Xunit;

namespace SshNet.Agent.Tests
{
    /// <summary>
    /// Golden-byte tests for the agent protocol encoding, driven through a fake
    /// in-process agent. The expected values come from the checked-in .pub files,
    /// which are an independent encoding of the same key material.
    /// </summary>
    public class ProtocolEncodingTests
    {
        private const byte Ssh2AgentcAddIdentity = 17;
        private const byte Ssh2AgentcSignRequest = 13;
        private const byte Ssh2AgentIdentitiesAnswer = 12;
        private const byte Ssh2AgentSignResponse = 14;
        private const byte SshAgentSuccess = 6;

        private static PrivateKeyFile PrivateKey(string name)
        {
            return new PrivateKeyFile(TestKeys.PrivateKeyPath(name));
        }

        private static WireReader RecordAddIdentity(string keyName)
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });
            fake.CreateClient().AddIdentity(PrivateKey(keyName));
            return new WireReader(fake.SingleRequest());
        }

        private static BigInteger FromMpint(byte[] bigEndian)
        {
            return new BigInteger(bigEndian, isUnsigned: false, isBigEndian: true);
        }

        [Fact]
        public void AddIdentity_Ed25519_MatchesPublicKeyBlob()
        {
            var blob = new WireReader(TestKeys.PublicKeyBlob(TestKeys.Ed25519Puttygen));
            Assert.Equal("ssh-ed25519", blob.Text());
            var expectedPublicKey = blob.Str();

            var request = RecordAddIdentity(TestKeys.Ed25519Puttygen);

            Assert.Equal(Ssh2AgentcAddIdentity, request.Byte());
            Assert.Equal("ssh-ed25519", request.Text());
            Assert.Equal(expectedPublicKey, request.Str());
            var privateKey = request.Str();
            Assert.Equal(64, privateKey.Length);
            Assert.Equal(expectedPublicKey, privateKey.Skip(32).ToArray());
            request.Str(); // comment
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void AddIdentity_Ed25519WithLeadingZero_KeepsTheZeroByte()
        {
            var blob = new WireReader(TestKeys.PublicKeyBlob(TestKeys.Ed25519ZeroLead));
            blob.Text();
            var expectedPublicKey = blob.Str();
            Assert.Equal(0, expectedPublicKey[0]);

            var request = RecordAddIdentity(TestKeys.Ed25519ZeroLead);

            request.Byte();
            request.Text();
            Assert.Equal(expectedPublicKey, request.Str());
        }

        [Fact]
        public void AddIdentity_Rsa_EncodesModulusAndExponentFromThePublicKey()
        {
            var blob = new WireReader(TestKeys.PublicKeyBlob(TestKeys.Rsa));
            Assert.Equal("ssh-rsa", blob.Text());
            var expectedExponent = FromMpint(blob.Str());
            var expectedModulus = FromMpint(blob.Str());

            var request = RecordAddIdentity(TestKeys.Rsa);

            Assert.Equal(Ssh2AgentcAddIdentity, request.Byte());
            Assert.Equal("ssh-rsa", request.Text());
            var modulus = FromMpint(request.Str());
            var exponent = FromMpint(request.Str());
            var d = FromMpint(request.Str());
            var iqmp = FromMpint(request.Str());
            var p = FromMpint(request.Str());
            var q = FromMpint(request.Str());
            request.Str(); // comment
            Assert.True(request.AtEnd);

            Assert.Equal(expectedModulus, modulus);
            Assert.Equal(expectedExponent, exponent);
            Assert.Equal(modulus, p * q);
            Assert.True(d > BigInteger.One);
            Assert.Equal(BigInteger.One, iqmp * q % p);
        }

        [Fact]
        public void AddIdentity_Ecdsa_EncodesCurveNameAndPointFromThePublicKey()
        {
            var blob = new WireReader(TestKeys.PublicKeyBlob(TestKeys.Ecdsa));
            Assert.Equal("ecdsa-sha2-nistp256", blob.Text());
            Assert.Equal("nistp256", blob.Text());
            var expectedPoint = blob.Str();

            var request = RecordAddIdentity(TestKeys.Ecdsa);

            Assert.Equal(Ssh2AgentcAddIdentity, request.Byte());
            Assert.Equal("ecdsa-sha2-nistp256", request.Text());
            Assert.Equal("nistp256", request.Text());
            Assert.Equal(expectedPoint, request.Str());
            var privateScalar = request.Str();
            Assert.NotEmpty(privateScalar);
            request.Str(); // comment
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void Sign_Rsa_RequestsRsaSha2_512()
        {
            using var fake = new FakeAgent();
            var blob = TestKeys.PublicKeyBlob(TestKeys.Rsa);
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentIdentitiesAnswer },
                Wire.U32(1),
                Wire.Str(blob), Wire.Str("rsa key")));
            var identity = Assert.Single(fake.CreateClient().RequestIdentities());
            var algorithm = (KeyHostAlgorithm)identity.HostKeyAlgorithms.First();
            Assert.Equal("rsa-sha2-512", algorithm.Name);

            var signatureBlob = new byte[] { 0xca, 0xfe, 0xba, 0xbe };
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentSignResponse },
                Wire.Str(Wire.Cat(Wire.Str("rsa-sha2-512"), Wire.Str(signatureBlob)))));
            var data = new byte[] { 1, 2, 3, 4 };

            var signature = algorithm.Sign(data);

            // the algorithm wraps the agent's raw signature in the SSH signature encoding
            Assert.Equal(Wire.Cat(Wire.Str("rsa-sha2-512"), Wire.Str(signatureBlob)), signature);
            fake.Requests.TryDequeue(out _); // the request-identities message
            Assert.True(fake.Requests.TryDequeue(out var raw));
            var request = new WireReader(raw!);
            Assert.Equal(Ssh2AgentcSignRequest, request.Byte());
            Assert.Equal(blob, request.Str());
            Assert.Equal(data, request.Str());
            Assert.Equal(4u, request.U32()); // SSH_AGENT_RSA_SHA2_512
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void Sign_Ed25519_RequestsWithoutFlags()
        {
            using var fake = new FakeAgent();
            var blob = TestKeys.PublicKeyBlob(TestKeys.Ed25519Puttygen);
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentIdentitiesAnswer },
                Wire.U32(1),
                Wire.Str(blob), Wire.Str("ed25519 key")));
            var identity = Assert.Single(fake.CreateClient().RequestIdentities());
            var algorithm = (KeyHostAlgorithm)identity.HostKeyAlgorithms.First();
            Assert.Equal("ssh-ed25519", algorithm.Name);

            var signatureBlob = new byte[64];
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentSignResponse },
                Wire.Str(Wire.Cat(Wire.Str("ssh-ed25519"), Wire.Str(signatureBlob)))));

            var signature = algorithm.Sign(new byte[] { 1, 2, 3, 4 });

            // the algorithm wraps the agent's raw signature in the SSH signature encoding
            Assert.Equal(Wire.Cat(Wire.Str("ssh-ed25519"), Wire.Str(signatureBlob)), signature);
            fake.Requests.TryDequeue(out _);
            Assert.True(fake.Requests.TryDequeue(out var raw));
            var request = new WireReader(raw!);
            Assert.Equal(Ssh2AgentcSignRequest, request.Byte());
            request.Str(); // key blob
            request.Str(); // data
            Assert.Equal(0u, request.U32());
        }

        [Fact]
        public void Sign_FidoKey_ReturnsTheAgentBlobVerbatim()
        {
            using var fake = new FakeAgent();
            var blob = Wire.Cat(
                Wire.Str("sk-ssh-ed25519@openssh.com"),
                Wire.Str(new byte[32]),
                Wire.Str("ssh:"));
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentIdentitiesAnswer },
                Wire.U32(1),
                Wire.Str(blob), Wire.Str("fido key")));
            var identity = Assert.Single(fake.CreateClient().RequestIdentities());
            var algorithm = identity.HostKeyAlgorithms.First();
            Assert.Equal("sk-ssh-ed25519@openssh.com", algorithm.Name);

            // string algorithm, string signature, byte flags, uint32 counter
            var skSignature = Wire.Cat(
                Wire.Str("sk-ssh-ed25519@openssh.com"),
                Wire.Str(new byte[] { 0xca, 0xfe, 0xba, 0xbe }),
                new byte[] { 0x01 },        // SSH_SK_USER_PRESENCE_REQD
                Wire.U32(42));              // signature counter
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentSignResponse },
                Wire.Str(skSignature)));

            var signature = algorithm.Sign(new byte[] { 1, 2, 3, 4 });

            // the whole sk blob, flags and counter included, goes on the wire as-is
            Assert.Equal(skSignature, signature);
            fake.Requests.TryDequeue(out _); // request-identities
            Assert.True(fake.Requests.TryDequeue(out var raw));
            var request = new WireReader(raw!);
            Assert.Equal(Ssh2AgentcSignRequest, request.Byte());
            Assert.Equal(blob, request.Str());
            request.Str(); // data
            Assert.Equal(0u, request.U32()); // no sign flags for sk keys
        }

        [Fact]
        public void RemoveAllIdentities_SendsTheBareMessage()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });

            fake.CreateClient().RemoveAllIdentities();

            var request = new WireReader(fake.SingleRequest());
            Assert.Equal(19, request.Byte()); // SSH2_AGENTC_REMOVE_ALL_IDENTITIES
            Assert.True(request.AtEnd);
        }
    }
}

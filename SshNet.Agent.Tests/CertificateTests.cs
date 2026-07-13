using System.Linq;
using Renci.SshNet.Security;
using Xunit;

namespace SshNet.Agent.Tests
{
    /// <summary>
    /// OpenSSH certificates (*-cert-v01@openssh.com) as agent identities. The
    /// checked-in certificates were created with ssh-keygen -s test_ca.
    /// </summary>
    public class CertificateTests
    {
        private const string Ed25519Cert = "ed25519_puttygen-cert";
        private const string RsaCert = "rsa_a-cert";

        private const byte Ssh2AgentIdentitiesAnswer = 12;
        private const byte Ssh2AgentcSignRequest = 13;
        private const byte Ssh2AgentSignResponse = 14;
        private const byte Ssh2AgentcRemoveIdentity = 18;
        private const byte SshAgentSuccess = 6;

        private static FakeAgent FakeAgentWith(byte[] blob)
        {
            var fake = new FakeAgent();
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentIdentitiesAnswer },
                Wire.U32(1),
                Wire.Str(blob), Wire.Str("cert identity")));
            return fake;
        }

        [Fact]
        public void Ed25519Certificate_IsListedAsCertificateAlgorithm()
        {
            var blob = TestKeys.PublicKeyBlob(Ed25519Cert);
            using var fake = FakeAgentWith(blob);

            var identity = Assert.Single(fake.CreateClient().RequestIdentities());

            var algorithm = Assert.IsType<CertificateHostAlgorithm>(identity.HostKeyAlgorithms.First());
            Assert.Equal("ssh-ed25519-cert-v01@openssh.com", algorithm.Name);
            Assert.Equal(blob, algorithm.Data);
            Assert.Equal("cert identity", identity.Key.Comment);
        }

        [Fact]
        public void Ed25519Certificate_SignsWithTheCertificateBlob()
        {
            var blob = TestKeys.PublicKeyBlob(Ed25519Cert);
            using var fake = FakeAgentWith(blob);
            var identity = Assert.Single(fake.CreateClient().RequestIdentities());
            var algorithm = (CertificateHostAlgorithm)identity.HostKeyAlgorithms.First();

            var rawSignature = new byte[64];
            rawSignature[0] = 0xab;
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentSignResponse },
                Wire.Str(Wire.Cat(Wire.Str("ssh-ed25519"), Wire.Str(rawSignature)))));

            var signature = new WireReader(algorithm.Sign(new byte[] { 1, 2, 3 }));

            Assert.Equal("ssh-ed25519", signature.Text());
            Assert.Equal(rawSignature, signature.Str());

            fake.Requests.TryDequeue(out _); // the request-identities message
            Assert.True(fake.Requests.TryDequeue(out var raw));
            var request = new WireReader(raw!);
            Assert.Equal(Ssh2AgentcSignRequest, request.Byte());
            Assert.Equal(blob, request.Str()); // the whole certificate blob
            request.Str(); // data
            Assert.Equal(0u, request.U32());
        }

        [Fact]
        public void RsaCertificate_IsOfferedAsRsaSha2AndSignsWithSha2Flags()
        {
            var blob = TestKeys.PublicKeyBlob(RsaCert);
            using var fake = FakeAgentWith(blob);
            var identity = Assert.Single(fake.CreateClient().RequestIdentities());

            Assert.Equal(
                new[] { "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com" },
                identity.HostKeyAlgorithms.Select(algorithm => algorithm.Name));

            var rawSignature = new byte[256];
            fake.EnqueueResponse(Wire.Cat(
                new[] { Ssh2AgentSignResponse },
                Wire.Str(Wire.Cat(Wire.Str("rsa-sha2-512"), Wire.Str(rawSignature)))));

            identity.HostKeyAlgorithms.First().Sign(new byte[] { 1, 2, 3 });

            fake.Requests.TryDequeue(out _);
            Assert.True(fake.Requests.TryDequeue(out var raw));
            var request = new WireReader(raw!);
            Assert.Equal(Ssh2AgentcSignRequest, request.Byte());
            Assert.Equal(blob, request.Str());
            request.Str(); // data
            Assert.Equal(4u, request.U32()); // SSH_AGENT_RSA_SHA2_512
        }

        [Fact]
        public void RemoveIdentity_RemovesByTheCertificateBlob()
        {
            var blob = TestKeys.PublicKeyBlob(Ed25519Cert);
            using var fake = FakeAgentWith(blob);
            var agent = fake.CreateClient();
            var identity = Assert.Single(agent.RequestIdentities());
            fake.EnqueueResponse(new[] { SshAgentSuccess });

            agent.RemoveIdentity(identity);

            fake.Requests.TryDequeue(out _);
            Assert.True(fake.Requests.TryDequeue(out var raw));
            var request = new WireReader(raw!);
            Assert.Equal(Ssh2AgentcRemoveIdentity, request.Byte());
            Assert.Equal(blob, request.Str());
            Assert.True(request.AtEnd);
        }
    }
}

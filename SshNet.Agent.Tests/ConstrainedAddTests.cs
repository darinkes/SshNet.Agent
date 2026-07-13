using System;
using Renci.SshNet;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class ConstrainedAddTests
    {
        private const byte Ssh2AgentcAddIdentity = 17;
        private const byte Ssh2AgentcAddIdConstrained = 25;
        private const byte ConstrainLifetime = 1;
        private const byte ConstrainConfirm = 2;
        private const byte SshAgentSuccess = 6;

        private static WireReader RecordAddIdentity(TimeSpan? lifetime, bool confirm)
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });
            var keyFile = new PrivateKeyFile(TestKeys.PrivateKeyPath(TestKeys.Ed25519Puttygen));

            fake.CreateClient().AddIdentity(keyFile, lifetime, confirm);

            return new WireReader(fake.SingleRequest());
        }

        private static WireReader SkipKeyAndComment(WireReader request)
        {
            request.Text(); // key type (ssh-ed25519)
            request.Str(); // public key
            request.Str(); // private key
            request.Str(); // comment
            return request;
        }

        [Fact]
        public void Lifetime_SendsTheConstrainedMessageWithSeconds()
        {
            var request = RecordAddIdentity(TimeSpan.FromMinutes(10), confirm: false);

            Assert.Equal(Ssh2AgentcAddIdConstrained, request.Byte());
            SkipKeyAndComment(request);
            Assert.Equal(ConstrainLifetime, request.Byte());
            Assert.Equal(600u, request.U32());
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void Confirm_SendsTheConstrainedMessage()
        {
            var request = RecordAddIdentity(lifetime: null, confirm: true);

            Assert.Equal(Ssh2AgentcAddIdConstrained, request.Byte());
            SkipKeyAndComment(request);
            Assert.Equal(ConstrainConfirm, request.Byte());
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void LifetimeAndConfirm_SendsBothConstraints()
        {
            var request = RecordAddIdentity(TimeSpan.FromSeconds(30), confirm: true);

            Assert.Equal(Ssh2AgentcAddIdConstrained, request.Byte());
            SkipKeyAndComment(request);
            Assert.Equal(ConstrainLifetime, request.Byte());
            Assert.Equal(30u, request.U32());
            Assert.Equal(ConstrainConfirm, request.Byte());
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void NoConstraints_StillSendsThePlainMessage()
        {
            var request = RecordAddIdentity(lifetime: null, confirm: false);

            Assert.Equal(Ssh2AgentcAddIdentity, request.Byte());
            SkipKeyAndComment(request);
            Assert.True(request.AtEnd);
        }
    }
}

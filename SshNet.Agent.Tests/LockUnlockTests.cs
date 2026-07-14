using System;
using System.Text;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class LockUnlockTests
    {
        private const byte SshAgentcLock = 22;
        private const byte SshAgentcUnlock = 23;
        private const byte SshAgentSuccess = 6;

        [Fact]
        public void Lock_SendsThePassphrase()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });

            fake.CreateClient().Lock("correct horse battery staple");

            var request = new WireReader(fake.SingleRequest());
            Assert.Equal(SshAgentcLock, request.Byte());
            Assert.Equal("correct horse battery staple", request.Text());
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void Unlock_SendsThePassphrase()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });

            fake.CreateClient().Unlock("correct horse battery staple");

            var request = new WireReader(fake.SingleRequest());
            Assert.Equal(SshAgentcUnlock, request.Byte());
            Assert.Equal("correct horse battery staple", request.Text());
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void Unlock_WithTheWrongPassphrase_Throws()
        {
            // an unconfigured FakeAgent answers with SSH_AGENT_FAILURE, like a
            // real agent does on a wrong passphrase
            using var fake = new FakeAgent();

            Assert.Throws<SshAgentFailureException>(() => fake.CreateClient().Unlock("wrong"));
        }
    }
}

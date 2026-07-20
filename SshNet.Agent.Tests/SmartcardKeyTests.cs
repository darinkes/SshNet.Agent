using System;
using System.Threading.Tasks;
using Xunit;

namespace SshNet.Agent.Tests
{
    public class SmartcardKeyTests
    {
        private const byte SshAgentcAddSmartcardKey = 20;
        private const byte SshAgentcRemoveSmartcardKey = 21;
        private const byte SshAgentcAddSmartcardKeyConstrained = 26;
        private const byte ConstrainLifetime = 1;
        private const byte ConstrainConfirm = 2;
        private const byte SshAgentSuccess = 6;

        [Fact]
        public void AddSmartcardIdentity_SendsProviderAndPin()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });

            fake.CreateClient().AddSmartcardIdentity("/usr/lib/opensc-pkcs11.so", "1234");

            var request = new WireReader(fake.SingleRequest());
            Assert.Equal(SshAgentcAddSmartcardKey, request.Byte());
            Assert.Equal("/usr/lib/opensc-pkcs11.so", request.Text());
            Assert.Equal("1234", request.Text());
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void AddSmartcardIdentity_WithConstraints_SendsTheConstrainedMessage()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });

            fake.CreateClient().AddSmartcardIdentity("provider.dll", "1234", TimeSpan.FromMinutes(10), confirm: true);

            var request = new WireReader(fake.SingleRequest());
            Assert.Equal(SshAgentcAddSmartcardKeyConstrained, request.Byte());
            Assert.Equal("provider.dll", request.Text());
            Assert.Equal("1234", request.Text());
            Assert.Equal(ConstrainLifetime, request.Byte());
            Assert.Equal(600u, request.U32());
            Assert.Equal(ConstrainConfirm, request.Byte());
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void RemoveSmartcardIdentity_SendsProviderAndPin()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });

            fake.CreateClient().RemoveSmartcardIdentity("provider.dll");

            var request = new WireReader(fake.SingleRequest());
            Assert.Equal(SshAgentcRemoveSmartcardKey, request.Byte());
            Assert.Equal("provider.dll", request.Text());
            Assert.Equal("", request.Text());
            Assert.True(request.AtEnd);
        }

        [Fact]
        public void AddSmartcardIdentity_WhenAgentFails_Throws()
        {
            using var fake = new FakeAgent();

            Assert.Throws<SshAgentFailureException>(
                () => fake.CreateClient().AddSmartcardIdentity("provider.dll", "1234"));
        }

        [Fact]
        public async Task AddSmartcardIdentityAsync_WithConstraints_SendsTheSameMessageAsTheSyncApi()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });

            await fake.CreateClient().AddSmartcardIdentityAsync("provider.dll", "1234",
                TimeSpan.FromMinutes(10), confirm: true, cancellationToken: TestContext.Current.CancellationToken);

            var request = new WireReader(fake.SingleRequest());
            Assert.Equal(SshAgentcAddSmartcardKeyConstrained, request.Byte());
            Assert.Equal("provider.dll", request.Text());
            Assert.Equal("1234", request.Text());
            Assert.Equal(ConstrainLifetime, request.Byte());
            Assert.Equal(600u, request.U32());
            Assert.Equal(ConstrainConfirm, request.Byte());
            Assert.True(request.AtEnd);
        }

        [Fact]
        public async Task RemoveSmartcardIdentityAsync_SendsProviderAndPin()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(new[] { SshAgentSuccess });

            await fake.CreateClient().RemoveSmartcardIdentityAsync("provider.dll",
                cancellationToken: TestContext.Current.CancellationToken);

            var request = new WireReader(fake.SingleRequest());
            Assert.Equal(SshAgentcRemoveSmartcardKey, request.Byte());
            Assert.Equal("provider.dll", request.Text());
            Assert.Equal("", request.Text());
            Assert.True(request.AtEnd);
        }
    }
}

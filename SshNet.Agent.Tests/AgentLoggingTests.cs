using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Xunit;

namespace SshNet.Agent.Tests
{
    /// <summary>
    /// An attached ILogger sees every raw agent message at Trace level as
    /// structured SshAgentTraceMessage state, one entry per request and one
    /// per response, each including the length prefix.
    /// </summary>
    public class AgentLoggingTests
    {
        private const byte Ssh2AgentIdentitiesAnswer = 12;

        private static byte[] Framed(byte[] payload)
        {
            return Wire.Cat(Wire.U32((uint)payload.Length), payload);
        }

        private sealed class CollectingLogger : ILogger
        {
            public bool Enabled { get; set; } = true;

            public List<(LogLevel Level, EventId EventId, SshAgentTraceMessage Message, string Text)> Entries { get; } = new();

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => Enabled;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var message = Assert.IsType<SshAgentTraceMessage>(state);
                Entries.Add((logLevel, eventId, message, formatter(state, exception)));
            }
        }

        [Fact]
        public void Send_LogsTheRequestAndTheResponse()
        {
            using var fake = new FakeAgent();
            var answer = Wire.Cat(new[] { Ssh2AgentIdentitiesAnswer }, Wire.U32(0));
            fake.EnqueueResponse(answer);
            var logger = new CollectingLogger();
            var agent = fake.CreateClient();
            agent.Logger = logger;

            agent.RequestIdentities();

            Assert.Equal(2, logger.Entries.Count);
            var request = logger.Entries[0];
            Assert.Equal(LogLevel.Trace, request.Level);
            Assert.Equal("AgentMessage", request.EventId.Name);
            Assert.Equal(SshAgentTraceDirection.Request, request.Message.Direction);
            Assert.Equal(Framed(fake.SingleRequest()), request.Message.Data);
            Assert.Equal("Request agent message, 5 bytes", request.Text);

            var response = logger.Entries[1];
            Assert.Equal(SshAgentTraceDirection.Response, response.Message.Direction);
            Assert.Equal(Framed(answer), response.Message.Data);
        }

        [Fact]
        public async Task SendAsync_LogsTheRequestAndTheResponse()
        {
            using var fake = new FakeAgent();
            var answer = Wire.Cat(new[] { Ssh2AgentIdentitiesAnswer }, Wire.U32(0));
            fake.EnqueueResponse(answer);
            var logger = new CollectingLogger();
            var agent = fake.CreateClient();
            agent.Logger = logger;

            await agent.RequestIdentitiesAsync(TestContext.Current.CancellationToken);

            Assert.Equal(2, logger.Entries.Count);
            Assert.Equal(SshAgentTraceDirection.Request, logger.Entries[0].Message.Direction);
            Assert.Equal(Framed(fake.SingleRequest()), logger.Entries[0].Message.Data);
            Assert.Equal(SshAgentTraceDirection.Response, logger.Entries[1].Message.Direction);
            Assert.Equal(Framed(answer), logger.Entries[1].Message.Data);
        }

        [Fact]
        public void DisabledLogger_SeesNothing()
        {
            using var fake = new FakeAgent();
            fake.EnqueueResponse(Wire.Cat(new[] { Ssh2AgentIdentitiesAnswer }, Wire.U32(0)));
            var logger = new CollectingLogger { Enabled = false };
            var agent = fake.CreateClient();
            agent.Logger = logger;

            agent.RequestIdentities();

            Assert.Empty(logger.Entries);
        }

        [Fact]
        public void TraceMessage_ExposesStructuredProperties()
        {
            var data = new byte[] { 0, 0, 0, 1, 11 };
            var message = new SshAgentTraceMessage(SshAgentTraceDirection.Request, data);

            var properties = new Dictionary<string, object?>();
            foreach (var pair in message)
                properties[pair.Key] = pair.Value;

            Assert.Equal(SshAgentTraceDirection.Request, properties["Direction"]);
            Assert.Equal(5, properties["DataLength"]);
            Assert.Equal(data, properties["Data"]);
            Assert.Equal("{Direction} agent message, {DataLength} bytes", properties["{OriginalFormat}"]);
        }
    }
}

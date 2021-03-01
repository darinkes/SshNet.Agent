using System.Collections.Generic;
using Renci.SshNet;
using SshNet.Agent.AgentMessage;
using SshNet.Agent.Keys;

namespace SshNet.Agent
{
    public sealed class Agent
    {
        private readonly string _socketPath;

        public Agent() : this(AgentSocketPath.GetPath())
        {
        }

        public Agent(string socketPath)
        {
            _socketPath = socketPath;
        }

        public IEnumerable<AgentIdentity> RequestIdentities()
        {
            return (IEnumerable<AgentIdentity>)Send(new RequestIdentities(this));
        }

        public void RemoveAllIdentities()
        {
            _ = Send(new RemoveIdentity(RemoveIdentityMode.All));
        }

        public void AddIdentity(PrivateKeyFile keyFile)
        {
            _ = Send(new AddIdentity(keyFile));
        }

        public byte[] Sign(IAgentKey key, byte[] data)
        {
            return (byte[])Send(new RequestSign(key, data));
        }

        private object Send(IAgentMessage message)
        {
            using var socketStream = new AgentSocketStream(_socketPath);
            using var writer = new AgentWriter(socketStream);
            using var reader = new AgentReader(socketStream);

            message.To(writer);
            return message.From(reader);
        }
    }
}
#if NETSTANDARD
using System;
using System.Runtime.InteropServices;
#endif
using SshNet.Agent.AgentMessage;

namespace SshNet.Agent
{
    public class Pageant : SshAgent
    {
        public Pageant()
        {
#if NETSTANDARD
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new NotSupportedException("Pageant is Windows only");
            }
#endif
        }

        internal override object? Send(IAgentMessage message)
        {
            using var socketStream = new PageantSocketStream();
            using var writer = new AgentWriter(socketStream);
            using var reader = new AgentReader(socketStream);

            message.To(writer);
            socketStream.Send();
            return message.From(reader);
        }
    }
}
#if NETSTANDARD
using System;
using System.Runtime.InteropServices;
#endif
using System.Threading;
using System.Threading.Tasks;
using SshNet.Agent.AgentMessage;

namespace SshNet.Agent
{
    /// <summary>
    /// Talks to PuTTY's Pageant over its WM_COPYDATA window message interface
    /// instead of a socket. Windows only.
    /// </summary>
    public class Pageant : SshAgent
    {
        /// <summary>Creates the client; Pageant itself must already be running.</summary>
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

        internal override Task<object?> SendAsync(IAgentMessage message, CancellationToken cancellationToken)
        {
            // Pageant is driven by a window message, which has no asynchronous
            // form; the memory-mapped hand-off completes synchronously anyway
            return Task.FromResult(Send(message));
        }
    }
}
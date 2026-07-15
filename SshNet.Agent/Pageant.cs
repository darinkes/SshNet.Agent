using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
#if !NETFRAMEWORK
using System.Runtime.InteropServices;
#endif
using System.Threading;
using System.Threading.Tasks;
using SshNet.Agent.AgentMessage;

namespace SshNet.Agent
{
    /// <summary>
    /// Talks to PuTTY's Pageant. Pageant 0.77+ serves the OpenSSH agent protocol
    /// on a named pipe, which is preferred (real async I/O, no 8 KB message
    /// limit); otherwise it falls back to the legacy WM_COPYDATA window message
    /// interface. Windows only.
    /// </summary>
    public class Pageant : SshAgent
    {
        private const string PipeDirectory = @"\\.\pipe\";
        private const string PipePrefix = "pageant.";

        // set when a Pageant named pipe was found; then the base SshAgent pipe
        // transport is used instead of WM_COPYDATA
        private readonly bool _useNamedPipe;

        /// <summary>
        /// Creates the client; Pageant itself must already be running. The
        /// timeout applies to the named pipe transport (connect and each read
        /// and write) and defaults to 10 seconds; it is unused in the
        /// synchronous WM_COPYDATA fallback.
        /// </summary>
        public Pageant(TimeSpan? timeout = null)
            : this(FindNamedPipe(), timeout)
        {
        }

        /// <summary>
        /// Creates a client bound to a specific transport: <paramref name="namedPipe"/>
        /// is the Pageant OpenSSH named pipe to talk to, or null to use the legacy
        /// WM_COPYDATA interface. The timeout applies to the named pipe transport
        /// and is unused for WM_COPYDATA.
        /// </summary>
        public Pageant(string? namedPipe, TimeSpan? timeout)
            // the placeholder socket path is never read in the WM_COPYDATA fallback
            : base(namedPipe ?? "pageant", timeout)
        {
#if !NETFRAMEWORK
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new NotSupportedException("Pageant is Windows only");
            }
#endif
            _useNamedPipe = namedPipe is not null;
        }

        /// <summary>
        /// Whether the OpenSSH named pipe transport is in use; false means the
        /// legacy WM_COPYDATA fallback. Internal for testing.
        /// </summary>
        internal bool UsesNamedPipe => _useNamedPipe;

        /// <summary>
        /// Finds a running Pageant's OpenSSH pipe, or null to fall back to
        /// WM_COPYDATA. Pageant's pipe is \\.\pipe\pageant.&lt;user&gt;.&lt;hash&gt;;
        /// the hash is deliberately awkward to recompute, so the pipe is found by
        /// listing the namespace, like the WM_COPYDATA path finds the window. The
        /// OS pattern keeps other processes' oddly named pipes out of the
        /// enumeration, which can otherwise trip path normalization.
        /// </summary>
        private static string? FindNamedPipe()
        {
#if !NETFRAMEWORK
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return null;
            }
#endif
            string[] entries;
            try
            {
                entries = Directory.GetFiles(PipeDirectory, PipePrefix + "*");
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return null; // namespace not listable, fall back to WM_COPYDATA
            }
            return SelectPipe(entries.Select(Path.GetFileName), Environment.UserName);
        }

        /// <summary>
        /// Picks a Pageant pipe from the candidates, preferring one that carries
        /// the current user name (several users can each run a Pageant). Returns
        /// null when none match. Internal for testing.
        /// </summary>
        internal static string? SelectPipe(IEnumerable<string?> names, string user)
        {
            var pipes = names
                .Where(n => n != null && n.StartsWith(PipePrefix, StringComparison.OrdinalIgnoreCase))
                .Select(n => n!)
                .ToList();
            if (pipes.Count == 0)
                return null;
            return pipes.FirstOrDefault(n => n.IndexOf(user, StringComparison.OrdinalIgnoreCase) >= 0) ?? pipes[0];
        }

        internal override object? Send(IAgentMessage message)
        {
            if (_useNamedPipe)
                return base.Send(message);

            using var socketStream = new PageantSocketStream();
            using var writer = new AgentWriter(socketStream);
            using var reader = new AgentReader(socketStream);

            message.To(writer);
            socketStream.Send();
            return message.From(reader);
        }

        internal override Task<object?> SendAsync(IAgentMessage message, CancellationToken cancellationToken)
        {
            if (_useNamedPipe)
                return base.SendAsync(message, cancellationToken);

            // WM_COPYDATA is driven by a window message, which has no asynchronous
            // form; the memory-mapped hand-off completes synchronously anyway
            return Task.FromResult(Send(message));
        }
    }
}

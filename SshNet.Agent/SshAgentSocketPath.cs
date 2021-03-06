using System;
using System.Runtime.InteropServices;

namespace SshNet.Agent
{
    internal static class AgentSocketPath
    {
        internal static string GetPath()
        {
#if NETSTANDARD
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
#endif
                return "openssh-ssh-agent";
#if NETSTANDARD
            var env = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
            if (env is null)
                throw new Exception("Unable to find ssh-agent socket path");
            return env;
#endif
        }
    }
}
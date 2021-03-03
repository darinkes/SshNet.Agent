using System;
using System.Runtime.InteropServices;

namespace SshNet.Agent
{
    internal class AgentSocketPath
    {
        internal static string GetPath()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return "openssh-ssh-agent";
            var env = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
            if (env is null)
                throw new Exception("Unable to find ssh-agent socket path");
            return env;
        }
    }
}
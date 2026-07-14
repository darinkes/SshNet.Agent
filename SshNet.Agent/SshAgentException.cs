using System;

namespace SshNet.Agent
{
    /// <summary>Thrown when communication with the key agent fails.</summary>
    public class SshAgentException : Exception
    {
        /// <summary>Creates the exception with a message describing the failure.</summary>
        public SshAgentException(string message) : base(message)
        {
        }

        /// <summary>Creates the exception with a message and the causing exception.</summary>
        public SshAgentException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    /// <summary>
    /// Thrown when the agent does not answer a request with the expected message,
    /// most commonly SSH_AGENT_FAILURE: the agent is locked, the user declined a
    /// confirmation prompt, or the agent rejected the request.
    /// </summary>
    public class SshAgentFailureException : SshAgentException
    {
        /// <summary>Creates the exception with a message naming the unexpected answer.</summary>
        public SshAgentFailureException(string message) : base(message)
        {
        }
    }
}

namespace SshNet.Agent
{
    /// <summary>The direction of a traced agent protocol message.</summary>
    public enum SshAgentTraceDirection
    {
        /// <summary>A request sent to the agent.</summary>
        Request,

        /// <summary>A response received from the agent.</summary>
        Response,
    }
}

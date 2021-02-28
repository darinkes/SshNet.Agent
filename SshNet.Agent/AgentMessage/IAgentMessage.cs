namespace SshNet.Agent.AgentMessage
{
    internal interface IAgentMessage
    {
        public void To(AgentWriter writer);

        public object From(AgentReader reader);
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using Renci.SshNet.Security;
using SshNet.Agent.Keys;

namespace SshNet.Agent.AgentMessage
{
    internal class RequestIdentities : IAgentMessage
    {
        private readonly SshAgent _agent;

        public RequestIdentities(SshAgent agent)
        {
            _agent = agent;
        }

        public void To(AgentWriter writer)
        {
            writer.Write((uint)1);
            writer.Write((byte)AgentMessageType.SSH2_AGENTC_REQUEST_IDENTITIES);
        }

        public object From(AgentReader reader)
        {
            _ = reader.ReadUInt32(); // msglen
            var answer = (AgentMessageType)reader.ReadByte();
            if (answer != AgentMessageType.SSH2_AGENT_IDENTITIES_ANSWER)
                throw new Exception($"Wrong Answer {answer}");

            var keys = new List<SshAgentPrivateKey>();
            var numKeys = reader.ReadUInt32();
            for (var i = 0; i < numKeys; i++)
            {
                var keyData = reader.ReadStringAsBytes();
                var comment = reader.ReadString();
                using var keyStream = new MemoryStream(keyData);
                using var keyReader = new AgentReader(keyStream);

                var keyType = keyReader.ReadString();
                Key key;
                switch (keyType)
                {
                    case "ssh-rsa":
                        key = new RsaAgentKey(_agent, keyData);
                        break;
                    case "ecdsa-sha2-nistp256":
                        // Fallthrough
                    case "ecdsa-sha2-nistp384":
                        // Fallthrough
                    case "ecdsa-sha2-nistp521":
                        key = new EcdsaAgentKey(_agent, keyData);
                        break;
                    case "ssh-ed25519":
                        key = new ED25519AgentKey(_agent, keyData);
                        break;
                    default:
                        // an agent may also hold key types this library cannot use, e.g.
                        // FIDO keys (sk-*) or certificates (*-cert-v01@openssh.com);
                        // leave those to other clients instead of failing the whole list
                        continue;
                }
                key.Comment = comment;
                keys.Add(new SshAgentPrivateKey(_agent, key));
            }

            return keys.ToArray();
        }
    }
}
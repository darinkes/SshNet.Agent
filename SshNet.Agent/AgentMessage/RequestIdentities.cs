using System;
using System.Collections.Generic;
using System.IO;
using Renci.SshNet;
using SshNet.Agent.Keys;

namespace SshNet.Agent.AgentMessage
{
    internal class RequestIdentities : IAgentMessage
    {
        private readonly Agent _agent;

        public RequestIdentities(Agent agent)
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

            var keys = new List<AgentIdentity>();
            var numKeys = reader.ReadUInt32();
            var i = 0;
            while (i < numKeys)
            {
                var keyData = reader.ReadStringAsBytes();
                using var keyStream = new MemoryStream(keyData);
                using var keyReader = new AgentReader(keyStream);

                var keyType = keyReader.ReadString();
                PrivateKeyFile key;
                switch (keyType)
                {
                    case "ssh-rsa":
                        var exponent = keyReader.ReadBignum();
                        var modulus = keyReader.ReadBignum();
                        key = new PrivateKeyFile(new RsaAgentKey(modulus, exponent, _agent, keyData));
                        break;
                    case "ecdsa-sha2-nistp256":
                        // Fallthrough
                    case "ecdsa-sha2-nistp384":
                        // Fallthrough
                    case "ecdsa-sha2-nistp521":
                        var curve = keyReader.ReadString();
                        var q = keyReader.ReadBignum2();
                        key = new PrivateKeyFile(new EcdsaAgentKey(curve, q, _agent, keyData));
                        break;
                    case "ssh-ed25519":
                        var pK = keyReader.ReadBignum2();
                        key = new PrivateKeyFile(new ED25519AgentKey(pK, _agent, keyData));
                        break;
                    default:
                        throw new Exception($"Unsupported KeyType {keyType}");
                }

                var comment = reader.ReadString();
                keys.Add(new AgentIdentity { Key = key, Comment = comment });
                i++;
            }

            return keys;
        }
    }
}
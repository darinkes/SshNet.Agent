using System;
using System.IO;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Security;

namespace SshNet.Agent.AgentMessage
{
    internal class AddIdentity : IAgentMessage
    {
        private readonly PrivateKeyFile _keyFile;

        public AddIdentity(PrivateKeyFile keyFile)
        {
            _keyFile = keyFile;
        }

        public void To(AgentWriter writer)
        {
            using var keyStream = new MemoryStream();
            using var keyWriter = new AgentWriter(keyStream);

            var key = ((KeyHostAlgorithm) _keyFile.HostKey).Key;
            keyWriter.EncodeString(key.ToString());
            switch (key)
            {
                case ED25519Key ed25519:
                    keyWriter.EncodeBignum2(ed25519.PublicKey);
                    keyWriter.EncodeBignum2(ed25519.PrivateKey);
                    break;
                case RsaKey rsa:
                    keyWriter.EncodeBignum2(rsa.Modulus.ToByteArray().Reverse());
                    keyWriter.EncodeBignum2(rsa.Exponent.ToByteArray().Reverse());
                    keyWriter.EncodeBignum2(rsa.D.ToByteArray().Reverse());
                    keyWriter.EncodeBignum2(rsa.InverseQ.ToByteArray().Reverse());
                    keyWriter.EncodeBignum2(rsa.P.ToByteArray().Reverse());
                    keyWriter.EncodeBignum2(rsa.Q.ToByteArray().Reverse());
                    break;
                case EcdsaKey ecdsa:
                    keyWriter.EncodeEcKey(ecdsa.Ecdsa);
                    break;
            }
            // comment
            keyWriter.EncodeString($"SshNet.Agent {key}");
            var keyData = keyStream.ToArray();

            writer.Write((uint)(1 + keyData.Length));
            writer.Write((byte)AgentMessageType.SSH2_AGENTC_ADD_IDENTITY);
            writer.Write(keyData);
        }

        public object From(AgentReader reader)
        {
            _ = reader.ReadUInt32(); // msglen
            var answer = (AgentMessageType)reader.ReadByte();
            if (answer != AgentMessageType.SSH_AGENT_SUCCESS)
                throw new Exception($"Wrong Answer {answer}");
            return null;
        }
    }
}
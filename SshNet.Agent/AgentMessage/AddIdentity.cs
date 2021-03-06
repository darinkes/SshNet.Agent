using System;
using System.IO;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Agent.Extensions;

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
            switch (key.ToString())
            {
                case "ssh-ed25519":
                    var ed25519 = (ED25519Key)key;
                    keyWriter.EncodeBignum2(ed25519.PublicKey);
                    keyWriter.EncodeBignum2(ed25519.PrivateKey);
                    break;
                case "ssh-rsa":
                    var rsa = (RsaKey)key;
                    keyWriter.EncodeBignum2(rsa.Modulus.ToByteArray().Reverse());
                    keyWriter.EncodeBignum2(rsa.Exponent.ToByteArray().Reverse());
                    keyWriter.EncodeBignum2(rsa.D.ToByteArray().Reverse());
                    keyWriter.EncodeBignum2(rsa.InverseQ.ToByteArray().Reverse());
                    keyWriter.EncodeBignum2(rsa.P.ToByteArray().Reverse());
                    keyWriter.EncodeBignum2(rsa.Q.ToByteArray().Reverse());
                    break;
                case "ecdsa-sha2-nistp256":
                // Fallthrough
                case "ecdsa-sha2-nistp384":
                // Fallthrough
                case "ecdsa-sha2-nistp521":
                    var ecdsa = (EcdsaKey)key;
                    var publicKey = ecdsa.Public;
                    keyWriter.EncodeString(publicKey[0].ToByteArray().Reverse());
                    keyWriter.EncodeString(publicKey[1].ToByteArray().Reverse());
                    keyWriter.EncodeBignum2(ecdsa.PrivateKey.ToBigInteger2().ToByteArray().Reverse());
                    break;
            }
            // comment
            keyWriter.EncodeString($"SshNet.Agent {key}");
            var keyData = keyStream.ToArray();

            writer.Write((uint)(1 + keyData.Length));
            writer.Write((byte)AgentMessageType.SSH2_AGENTC_ADD_IDENTITY);
            writer.Write(keyData);
        }

        public object? From(AgentReader reader)
        {
            _ = reader.ReadUInt32(); // msglen
            var answer = (AgentMessageType)reader.ReadByte();
            if (answer != AgentMessageType.SSH_AGENT_SUCCESS)
                throw new Exception($"Wrong Answer {answer}");
            return null;
        }
    }
}
using System;
using System.IO;
using System.Linq;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Agent.Extensions;

namespace SshNet.Agent.AgentMessage
{
    internal class AddIdentity : IAgentMessage
    {
        // draft-miller-ssh-agent, "Key Constraints"
        private const byte ConstrainLifetime = 1;
        private const byte ConstrainConfirm = 2;

        private readonly IPrivateKeySource _keyFile;
        private readonly TimeSpan? _lifetime;
        private readonly bool _confirm;

        public AddIdentity(IPrivateKeySource keyFile, TimeSpan? lifetime = null, bool confirm = false)
        {
            _keyFile = keyFile;
            _lifetime = lifetime;
            _confirm = confirm;
        }

        public void To(AgentWriter writer)
        {
            using var keyStream = new MemoryStream();
            using var keyWriter = new AgentWriter(keyStream);

            var key = ((KeyHostAlgorithm) _keyFile.HostKeyAlgorithms.First()).Key;
            keyWriter.EncodeString(key.ToString());
            switch (key.ToString())
            {
                case "ssh-ed25519":
                    var ed25519 = (ED25519Key)key;
                    keyWriter.EncodeBignum2(ed25519.PublicKey);
                    var privateKey = new byte[ed25519.PrivateKey.Length + ed25519.PublicKey.Length];
                    Buffer.BlockCopy(ed25519.PrivateKey, 0, privateKey, 0, ed25519.PrivateKey.Length);
                    Buffer.BlockCopy(ed25519.PublicKey, 0, privateKey, ed25519.PrivateKey.Length, ed25519.PublicKey.Length);
                    keyWriter.EncodeBignum2(privateKey);
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
            keyWriter.EncodeString(key.Comment ?? "");

            var messageType = AgentMessageType.SSH2_AGENTC_ADD_IDENTITY;
            if (_lifetime is not null || _confirm)
            {
                messageType = AgentMessageType.SSH2_AGENTC_ADD_ID_CONSTRAINED;
                if (_lifetime is not null)
                {
                    keyWriter.Write(ConstrainLifetime);
                    keyWriter.Write(Convert.ToUInt32(_lifetime.Value.TotalSeconds));
                }
                if (_confirm)
                    keyWriter.Write(ConstrainConfirm);
            }
            var keyData = keyStream.ToArray();

            writer.Write((uint)(1 + keyData.Length));
            writer.Write((byte)messageType);
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
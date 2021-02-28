using System;
using Renci.SshNet.Common;

namespace SshNet.Agent.Keys
{
    public class Ed25519AgentKey : AgentKey
    {
        public override string ToString()
        {
            return "ssh-ed25519";
        }

        public override BigInteger[] Public
        {
            get
            {
                return new BigInteger[] { PublicKey.ToBigInteger() };
            }
            set => throw new NotImplementedException();
        }

        public override int KeyLength => PublicKey.Length * 8;

        public byte[] PublicKey { get; }

        public Ed25519AgentKey(byte[] pk, Agent agent, byte[] keyData) : base(agent, keyData)
        {
            PublicKey = pk;
        }
    }
}
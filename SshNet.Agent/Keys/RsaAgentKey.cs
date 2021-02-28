using System;
using Renci.SshNet.Common;

namespace SshNet.Agent.Keys
{
    internal class RsaAgentKey : AgentKey
    {
        public override string ToString()
        {
            return "ssh-rsa";
        }

        public BigInteger Modulus => _privateKey[0];

        public BigInteger Exponent => _privateKey[1];

        public override int KeyLength => Modulus.BitLength;

        public override BigInteger[] Public
        {
            get
            {
                return new[] { Exponent, Modulus };
            }
            set => throw new NotImplementedException();
        }

        public RsaAgentKey(BigInteger modulus, BigInteger exponent, Agent agent, byte[] keyData) : base(agent, keyData)
        {
            _privateKey = new BigInteger[2];
            _privateKey[0] = modulus;
            _privateKey[1] = exponent;
        }
    }
}
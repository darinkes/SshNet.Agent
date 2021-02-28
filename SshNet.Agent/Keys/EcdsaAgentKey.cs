using System;
using System.Text;
using Renci.SshNet.Common;

namespace SshNet.Agent.Keys
{
    public class EcdsaAgentKey : AgentKey
    {
        private readonly byte[] _curve;
        private readonly byte[] _publicKey;

        public override string ToString()
        {
            return $"ecdsa-sha2-nistp{KeyLength}";
        }

        public override BigInteger[] Public {
            get
            {
                return new BigInteger[] {new BigInteger(_curve.Reverse()), new BigInteger(_publicKey.Reverse()) };
            }
            set => throw new NotImplementedException();
        }
        public override int KeyLength { get; }

        public EcdsaAgentKey(string curve, byte[] publicKey, Agent agent, byte[] keyData) : base(agent, keyData)
        {
            KeyLength = curve switch
            {
                "nistp521" => 521,
                "nistp384" => 384,
                "nistp256" => 256,
                _ => throw new Exception($"Unsupported Curve {curve}")
            };
            _curve = Encoding.ASCII.GetBytes(curve);
            _publicKey = publicKey;
        }
    }
}
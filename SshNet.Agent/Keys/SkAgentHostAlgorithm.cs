using System;
using Renci.SshNet.Security;

namespace SshNet.Agent.Keys
{
    /// <summary>
    /// A FIDO/security-key identity (sk-ecdsa-sha2-nistp256@openssh.com or
    /// sk-ssh-ed25519@openssh.com). SSH.NET has no <see cref="Key"/> type for
    /// these, so both the public-key blob and the signature (which carries the
    /// sk flags and counter) come straight from the agent, unchanged.
    /// </summary>
    internal class SkAgentHostAlgorithm : HostAlgorithm, IAgentKey
    {
        private readonly byte[] _keyData;

        public SshAgent Agent { get; }

        public byte[] KeyData => _keyData;

        public override byte[] Data => _keyData;

        public SkAgentHostAlgorithm(SshAgent agent, string name, byte[] keyData) : base(name)
        {
            Agent = agent;
            _keyData = keyData;
        }

        public override byte[] Sign(byte[] input)
        {
            return Agent.Sign(this, input, rawSignature: true);
        }

        public override bool VerifySignature(byte[] data, byte[] signature)
        {
            throw new NotSupportedException("Signature verification is done by the SSH server, not the agent.");
        }
    }
}

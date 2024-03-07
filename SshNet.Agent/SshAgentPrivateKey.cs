using System.Collections.Generic;
using System.Security.Cryptography;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Agent.Keys;

namespace SshNet.Agent
{
    public class SshAgentPrivateKey : IPrivateKeySource
    {
        private readonly List<HostAlgorithm> _hostAlgorithms = new();

        public IReadOnlyCollection<HostAlgorithm> HostKeyAlgorithms => _hostAlgorithms;

        public Key Key { get; }

        public SshAgentPrivateKey(SshAgent agent, Key key)
        {
            Key = key;
            _hostAlgorithms.Add(new KeyHostAlgorithm(key.ToString(), key));

            if (Key is not RsaAgentKey rsaKey)
                return;
            _hostAlgorithms.Add(new KeyHostAlgorithm("rsa-sha2-512", key, new RsaAgentSignature(agent, rsaKey, HashAlgorithmName.SHA512)));
            _hostAlgorithms.Add(new KeyHostAlgorithm("rsa-sha2-256", key, new RsaAgentSignature(agent, rsaKey, HashAlgorithmName.SHA256)));
        }
    }
}
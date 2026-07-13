using System;
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

            if (Key is RsaAgentKey rsaKey)
            {
                // Every algorithm offered costs one of the server's MaxAuthTries when the key
                // is not accepted, and OpenSSH 8.8+ rejects ssh-rsa (SHA-1) signatures, so
                // prefer SHA-2 and only offer ssh-rsa on request. See GitHub Issue #13.
                _hostAlgorithms.Add(new KeyHostAlgorithm("rsa-sha2-512", key, new RsaAgentSignature(agent, rsaKey, HashAlgorithmName.SHA512)));
                _hostAlgorithms.Add(new KeyHostAlgorithm("rsa-sha2-256", key, new RsaAgentSignature(agent, rsaKey, HashAlgorithmName.SHA256)));
                if (agent.IncludeLegacySshRsa)
                    _hostAlgorithms.Add(new KeyHostAlgorithm(key.ToString(), key));
                return;
            }

            _hostAlgorithms.Add(new KeyHostAlgorithm(key.ToString(), key));
        }

        public SshAgentPrivateKey(SshAgent agent, Certificate certificate, byte[] certificateData)
        {
            Key = certificate.Key;

            // signing echoes the whole certificate blob back to the agent
            var identity = new CertificateAgentIdentity(agent, certificateData);

            if (certificate.Name == "ssh-rsa-cert-v01@openssh.com")
            {
                // RFC 8332: the rsa-sha2-*-cert algorithms use the ssh-rsa-cert
                // blob format, so only the offered name and sign flags differ
                _hostAlgorithms.Add(new CertificateHostAlgorithm("rsa-sha2-512-cert-v01@openssh.com", Key, certificate, new RsaAgentSignature(agent, identity, HashAlgorithmName.SHA512)));
                _hostAlgorithms.Add(new CertificateHostAlgorithm("rsa-sha2-256-cert-v01@openssh.com", Key, certificate, new RsaAgentSignature(agent, identity, HashAlgorithmName.SHA256)));
                if (agent.IncludeLegacySshRsa)
                    _hostAlgorithms.Add(new CertificateHostAlgorithm(certificate.Name, Key, certificate, new RsaAgentSignature(agent, identity)));
                return;
            }

            _hostAlgorithms.Add(new CertificateHostAlgorithm(certificate.Name, Key, certificate, new AgentSignature(agent, identity)));
        }
    }
}
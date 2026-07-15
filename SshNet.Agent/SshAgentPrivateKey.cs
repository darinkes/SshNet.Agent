using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Agent.Keys;

namespace SshNet.Agent
{
    /// <summary>
    /// An identity held by the agent, usable as an SSH.NET private key source:
    /// signing is delegated to the agent, the private key never leaves it.
    /// </summary>
    public class SshAgentPrivateKey : IPrivateKeySource
    {
        private readonly List<HostAlgorithm> _hostAlgorithms = new();

        /// <summary>The host key algorithms this identity is offered with.</summary>
        public IReadOnlyCollection<HostAlgorithm> HostKeyAlgorithms => _hostAlgorithms;

        /// <summary>
        /// The public key; for certificates the key embedded in the certificate.
        /// <see langword="null"/> for FIDO/security keys (sk-*), which have no
        /// SSH.NET <see cref="Key"/> type.
        /// </summary>
        public Key? Key { get; }

        /// <summary>The comment the agent lists the identity under; empty when it has none.</summary>
        public string Comment { get; }

        /// <summary>The identity of a plain key held by the agent.</summary>
        public SshAgentPrivateKey(SshAgent agent, Key key)
        {
            Key = key;
            Comment = key.Comment ?? "";

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

        /// <summary>
        /// The identity of a FIDO/security key held by the agent
        /// (sk-ecdsa-sha2-nistp256@openssh.com or sk-ssh-ed25519@openssh.com).
        /// </summary>
        public SshAgentPrivateKey(SshAgent agent, byte[] keyData, string keyType, string comment = "")
        {
            Key = null; // no SSH.NET Key type for sk-* keys
            Comment = comment;
            _hostAlgorithms.Add(new SkAgentHostAlgorithm(agent, keyType, keyData));
        }

        /// <summary>
        /// The identity of an OpenSSH certificate held by the agent; the agent
        /// signs with the private key matching <paramref name="certificateData"/>.
        /// </summary>
        public SshAgentPrivateKey(SshAgent agent, Certificate certificate, byte[] certificateData)
        {
            Key = certificate.Key;
            Comment = certificate.Key.Comment ?? "";

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
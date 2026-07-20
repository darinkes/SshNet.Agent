SshNet.Agent
=============

[SSH.NET](https://github.com/sshnet/SSH.NET) Extension to authenticate via OpenSSH Agent and PuTTY Pageant

[![License](https://img.shields.io/github/license/darinkes/SshNet.Agent)](https://github.com/darinkes/SshNet.Agent/blob/main/LICENSE)
[![NuGet](https://img.shields.io/nuget/v/SshNet.Agent.svg?style=flat)](https://www.nuget.org/packages/SshNet.Agent)
![Nuget](https://img.shields.io/nuget/dt/SshNet.Agent)

![.NET-Ubuntu](https://github.com/darinkes/SshNet.Agent/workflows/.NET-Ubuntu/badge.svg)
![.NET-Windows](https://github.com/darinkes/SshNet.Agent/workflows/.NET-Windows/badge.svg)
![NuGet](https://github.com/darinkes/SshNet.Agent/workflows/NuGet/badge.svg)

## .NET Frameworks

* .NET 4.8
* netstandard 2.0
* netstandard 2.1
* .NET 8.0

Note: Only the netstandard 2.1 and .NET 8.0 builds contain support for Unix Domain Sockets to use ssh-agent on Linux.

## Keys
* ssh-ed25519
* ecdsa-sha2-nistp256
* ecdsa-sha2-nistp384
* ecdsa-sha2-nistp521
* ssh-rsa with 2048, 3072, 4096 or 8192 KeyLength
* sk-ssh-ed25519@openssh.com (FIDO/security key)
* sk-ecdsa-sha2-nistp256@openssh.com (FIDO/security key)

### FIDO / security keys

FIDO identities (`ssh-keygen -t ed25519-sk` / `-t ecdsa-sk`) held by the agent
are offered to the server automatically. The agent drives the authenticator, so
touch (and, for verify-required keys, the PIN) is prompted at sign time; the
private key never leaves the hardware. These identities have no SSH.NET `Key`,
so `SshAgentPrivateKey.Key` is `null` for them; their comment is still available
via `SshAgentPrivateKey.Comment`, which every identity carries.

### RSA and legacy ssh-rsa

RSA identities are offered as `rsa-sha2-512` and `rsa-sha2-256` (RFC 8332). The
legacy SHA-1 `ssh-rsa` signature algorithm is only offered when explicitly
enabled: it is needed solely for servers without RFC 8332 support (OpenSSH
older than 7.2), OpenSSH 8.8+ rejects it, and every offered algorithm costs one
of the server's `MaxAuthTries`.

```csharp
var agent = new SshAgent { IncludeLegacySshRsa = true };
```

## Features

- Auth
- Auth with OpenSSH Certificates
- Adding Keys
- Adding Keys with Constraints (lifetime, confirm)
- Adding and Removing PKCS#11 / Smartcard Keys
- Getting Keys
- Removing Keys
- Removing all Keys
- Locking and Unlocking the Agent
- Async API

## Agent Protocol Documentation
[draft-miller-ssh-agent-02](https://tools.ietf.org/html/draft-miller-ssh-agent-02)

## Usage

### OpenSSH Agent
```csharp
var agent = new SshAgent();

var keyFile = new PrivateKeyFile("test.key");
agent.AddIdentity(keyFile);

var keys = agent.RequestIdentities();

using var client = new SshClient("ssh.foo.com", "root", keys);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

### PuTTY Pageant
```csharp
var agent = new Pageant();

var keyFile = new PrivateKeyFile("test.key");
agent.AddIdentity(keyFile);

var keys = agent.RequestIdentities();

using var client = new SshClient("ssh.foo.com", "root", keys);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

`Pageant` automatically talks to Pageant 0.77+ over its OpenSSH named pipe when
one is available (real async I/O, no WM_COPYDATA 8 KB message limit), and falls
back to the legacy WM_COPYDATA interface otherwise. No code change is needed.

The `Pageant` class is Windows only (its transports, WM_COPYDATA and the Windows
named pipe, do not exist elsewhere). On Linux, PuTTY's `pageant` serves the
standard agent protocol on a unix socket, so use `SshAgent` instead: `pageant`
sets `SSH_AUTH_SOCK`, which `new SshAgent()` picks up, or pass the socket path to
`new SshAgent(path, null)`.

### OpenSSH Certificates

Certificate identities held by the agent (`*-cert-v01@openssh.com`) are offered
to the server automatically; the agent signs with the matching private key. To
add a key together with its certificate, load the certificate alongside the
private key:

```csharp
var agent = new SshAgent();

// test.key + the certificate signed by your CA (test-cert.pub)
agent.AddIdentity(new PrivateKeyFile("test.key", null, "test-cert.pub"));

var keys = agent.RequestIdentities();

// works against servers that trust the CA (TrustedUserCAKeys)
using var client = new SshClient("ssh.foo.com", "root", keys);
client.Connect();
```

### Minting Certificates with SshNet.Keygen

The certificate above can be produced in .NET with
[SshNet.Keygen](https://github.com/darinkes/SshNet.Keygen), so the whole
short-lived-certificate flow - mint, load into the agent, authenticate - stays
in one process without shelling out to `ssh-keygen`:

```csharp
// mint a short-lived user certificate for test.key, signed by your CA
var userKey = new PrivateKeyFile("test.key");
var certificate = new SshCertificateBuilder(userKey)
    .WithKeyId("root@example.com")
    .WithPrincipal("root")
    .WithValidity(DateTime.UtcNow, DateTime.UtcNow.AddHours(8))
    .SignWith(new PrivateKeyFile("ca"));

File.WriteAllText("test-cert.pub", certificate.ToOpenSshPublicFormat());

// load the key together with the freshly minted certificate ...
var agent = new SshAgent();
agent.AddIdentity(new PrivateKeyFile("test.key", null, "test-cert.pub"));

// ... and authenticate against a server that trusts the CA
using var client = new SshClient("ssh.foo.com", "root", agent.RequestIdentities());
client.Connect();
```

The same certificate can be served through an agent server, or used directly
with SSH.NET without an agent.

### Async

All agent operations are also available asynchronously and take an optional
`CancellationToken`:

```csharp
var agent = new SshAgent();

await agent.AddIdentityAsync(new PrivateKeyFile("test.key"), cancellationToken);
var keys = await agent.RequestIdentitiesAsync(cancellationToken);
await agent.RemoveAllIdentitiesAsync(cancellationToken);
```

Note: Signing during authentication stays synchronous, since SSH.NET calls it
through its synchronous `DigitalSignature` contract.

### Key Constraints

Keys can be added with the constraints known from `ssh-add -t` and `ssh-add -c`:

```csharp
var agent = new SshAgent();

// the agent removes the key after 10 minutes and asks for
// confirmation on every use
agent.AddIdentity(new PrivateKeyFile("test.key"), TimeSpan.FromMinutes(10), confirm: true);
```

### Locking and Unlocking

A locked agent hides its identities and refuses signing until it is unlocked
again, like `ssh-add -x`/`ssh-add -X`:

```csharp
var agent = new SshAgent();

agent.Lock("passphrase");
// agent.RequestIdentities() is empty now
agent.Unlock("passphrase");
```

### PKCS#11 / Smartcard Keys

Keys held on a PKCS#11 token can be added to and removed from the agent, like
`ssh-add -s`/`ssh-add -e`. The agent loads the key through the PKCS#11 provider
(a shared library path) and unlocks the token with the PIN; the private key
never leaves the token.

```csharp
var agent = new SshAgent();

// ssh-add -s /usr/lib/opensc-pkcs11.so
agent.AddSmartcardIdentity("/usr/lib/opensc-pkcs11.so", "1234");

var keys = agent.RequestIdentities();

// ssh-add -e /usr/lib/opensc-pkcs11.so
agent.RemoveSmartcardIdentity("/usr/lib/opensc-pkcs11.so");
```

Smartcard keys can be added with the same lifetime/confirm constraints as
regular keys:

```csharp
agent.AddSmartcardIdentity("/usr/lib/opensc-pkcs11.so", "1234", TimeSpan.FromMinutes(10), confirm: true);
```

## Resharper Warning

If you want to avoid the Resharper Warning "Co-variant array conversion": https://www.jetbrains.com/help/resharper/CoVariantArrayConversion.html

```csharp
var agent = new Pageant();

var keyFile = new PrivateKeyFile("test.key");
agent.AddIdentity(keyFile);

var keys = agent.RequestIdentities();

using var client = new SshClient("ssh.foo.com", "root", keys.ToArray<IPrivateKeySource>());
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

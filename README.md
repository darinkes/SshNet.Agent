SshNet.Agent
=============

[SSH.NET](https://github.com/sshnet/SSH.NET) Extension to authenticate via OpenSSH Agent and PuTTY Pageant

[![License](https://img.shields.io/github/license/darinkes/SshNet.Agent)](https://github.com/darinkes/SshNet.Agent/blob/main/LICENSE)

![CodeQL](https://github.com/darinkes/SshNet.Agent/workflows/CodeQL/badge.svg)
![.NET-Ubuntu](https://github.com/darinkes/SshNet.Agent/workflows/.NET-Ubuntu/badge.svg)
![.NET-Windows](https://github.com/darinkes/SshNet.Agent/workflows/.NET-Windows/badge.svg)

## Status

Works on my machine - WIP

Currently builds it's own fork of [SSH.NET](https://github.com/sshnet/SSH.NET).

Needs this Branch: https://github.com/darinkes/SSH.NET-1/tree/agent_auth

## .NET Frameworks

* .NET 4.0
* netstandard 2.0
* netstandard 2.1

Note: Only with netstandard 2.1 it contains support for Unix Domain Sockets to use ssh-agent on Linux.

## Keys
* ssh-ed25519
* ecdsa-sha2-nistp256
* ecdsa-sha2-nistp384
* ecdsa-sha2-nistp521
* ssh-rsa with 2048, 3072, 4096 or 8192 KeyLength

## Features

- Auth
- Adding Keys
- Getting Keys
- Removing Keys
- Removing all Keys

## Agent Protocol Documentation
[draft-miller-ssh-agent-02](https://tools.ietf.org/html/draft-miller-ssh-agent-02)

## Usage

### OpenSSH Agent
```csharp
var agent = new SshAgent();

var keyFile = new PrivateKeyFile("test.key");
agent.AddIdentity(keyFile);

var keys = agent.RequestIdentities().Select(i => i.Key).ToArray();

using var client = new SshClient("ssh.foo.com", "root", keys);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

### PuTTY Pageant
```csharp
var agent = new Pageant();

var keyFile = new PrivateKeyFile("test.key");
agent.AddIdentity(keyFile);

var keys = agent.RequestIdentities().Select(i => i.Key).ToArray();

using var client = new SshClient("ssh.foo.com", "root", keys);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

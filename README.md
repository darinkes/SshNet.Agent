SshNet.Agent
=============

[SSH.NET](https://github.com/sshnet/SSH.NET) Extension to authenticate via OpenSSH Agent

![CodeQL](https://github.com/darinkes/SshNet.Agent/workflows/CodeQL/badge.svg)
![.NET](https://github.com/darinkes/SshNet.Agent/workflows/.NET/badge.svg)

## Status

Works on my machine - WIP

Currently builds it's own fork of [SSH.NET](https://github.com/sshnet/SSH.NET).

Needs this Branch: https://github.com/darinkes/SSH.NET-1/tree/agent_auth

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
- Removing all Keys

## Agent Protocol Documentation
[draft-miller-ssh-agent-02](https://tools.ietf.org/html/draft-miller-ssh-agent-02)

## Usage

```csharp
var agent = new Agent();

var keyFile = new PrivateKeyFile("test.key");
agent.AddIdentity(keyFile);

var keys = agent.RequestIdentities().Select(i => i.Key).ToArray();

using var client = new SshClient("ssh.foo.com", "root", keys);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```
![](Noise.png)

[![Latest Version](NugetBadge.svg)](https://www.nuget.org/packages/Noise.NET)
[![Build Status](https://travis-ci.org/Metalnem/noise.svg?branch=master)](https://travis-ci.org/Metalnem/noise)
[![Build status](https://ci.appveyor.com/api/projects/status/aw4y7rackgepjy8u?svg=true)](https://ci.appveyor.com/project/Metalnem/noise)
[![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://raw.githubusercontent.com/metalnem/noise/master/LICENSE)

.NET Standard 2.0 implementation of the [Noise Protocol Framework](https://noiseprotocol.org/)
(revision 33 of the [spec](https://noiseprotocol.org/noise.html)).

## Usage

1. Include the Noise namespace.

```csharp
using Noise;
```

2. Choose the handshake pattern and cryptographic functions.

```csharp
var protocol = new Protocol(
  HandshakePattern.IK,
  CipherFunction.ChaChaPoly,
  HashFunction.Blake2b,
  PatternModifiers.Psk2
);
```

3. Start the handshake by instantiating the protocol with the necessary parameters.

```csharp
// s is communicated out-of-band
// psk is a pre-shared symmetric key

var initiator = protocol.Create(
  initiator: true,
  rs: rs,
  psks: new byte[][] { psk }
);

var responder = protocol.Create(
  initiator: false,
  s: s,
  psks: new byte[][] { psk }
);
```

4. Send and receive messages.

```csharp
(written, hash, transport) = state.WriteMessage(message, outputBuffer);
(read, hash, transport) = state.ReadMessage(received, inputBuffer);

written = transport.WriteMessage(message, outputBuffer);
read = transport.ReadMessage(received, inputBuffer);
```

## Installation

```
> dotnet add package Noise.NET --version 0.9.0-rc
```

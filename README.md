# JwtInspector - A Library for Decoding and Validating JWT Tokens

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![issues - jwt-inspector](https://img.shields.io/github/issues/engineering87/jwt-inspector)](https://github.com/engineering87/jwt-inspector/issues)
[![Nuget](https://img.shields.io/nuget/v/JwtInspector.Core?style=plastic)](https://www.nuget.org/packages/JwtInspector.Core)
![NuGet Downloads](https://img.shields.io/nuget/dt/JwtInspector.Core)
[![Build](https://github.com/engineering87/jwt-inspector/actions/workflows/dotnet.yml/badge.svg)](https://github.com/engineering87/jwt-inspector/actions/workflows/dotnet.yml)
[![stars - jwt-inspector](https://img.shields.io/github/stars/engineering87/jwt-inspector?style=social)](https://github.com/engineering87/jwt-inspector)

JwtInspector is a C# library that provides utilities for decoding, validating, and inspecting JWT (JSON Web Tokens). This library simplifies working with JWTs by providing easy-to-use methods for extracting data, validating tokens, and more. 

The library supports various use cases, such as decoding JWT payloads, validating token expiration, and verifying the authenticity of tokens using HMAC-SHA algorithms.

## Features

- Decode JWT tokens to extract headers, claims, and payload.
- Validate JWT authenticity, algorithm, and expiration.
- Support for handling standard claims:  
  - `iat` (issued at)  
  - `exp` (expiration)  
  - `nbf` (not before)  
  - `sub` (subject)  
  - `jti` (JWT ID)  
- Provides a unified interface for inspecting JWT headers, payloads, and signature presence.
- Easy-to-use helpers for Base64Url encoding/decoding.
- Safe and consistent return values (`string.Empty` instead of `null` for missing claims).
- Built-in validation methods for issuer, audience, claims, algorithm, signing key, and token lifetime.
- Strongly-typed deserialization of payload into custom objects.
- JSON summary of token contents for debugging and inspection.

## Installation

You can install the library via the NuGet package manager with the following command:

```bash
dotnet add package JwtInspector.Core
```

## Usage

### Decoding JWT Payload

To decode the payload of a JWT token and get a dictionary of claims:

```csharp
using JwtInspector.Core.Services;

var jwtInspector = new JwtInspectorService();
string token = "<your-jwt-token>";
var claims = jwtInspector.DecodePayloadAsJson(token);
Console.WriteLine(claims);
```

### Validating JWT Token

To validate a JWT token using a secret key:

```csharp
using JwtInspector.Core.Services;

var jwtInspector = new JwtInspectorService();
string token = "<your-jwt-token>";
string secretKey = "<your-secret-key>";
bool isValid = jwtInspector.ValidateToken(token, secretKey);
Console.WriteLine($"Token valid: {isValid}");
```

### Extracting JWT Parts

You can extract the header, payload, and signature from a JWT token:

```csharp
using JwtInspector.Core.Services;

var jwtInspector = new JwtInspectorService();
string token = "<your-jwt-token>";
var (header, payload, signature) = jwtInspector.ExtractJwtParts(token);
Console.WriteLine($"Header: {header}");
Console.WriteLine($"Payload: {payload}");
Console.WriteLine($"Signature: {signature}");
```

### Checking Token Expiration

To check if a JWT token is expired:

```csharp
using JwtInspector.Core.Services;

var jwtInspector = new JwtInspectorService();
string token = "<your-jwt-token>";
bool isExpired = jwtInspector.IsExpired(token);
Console.WriteLine($"Token expired: {isExpired}");
```

### Extracting JWT Claims

To get the claims from a JWT token:

```csharp
using JwtInspector.Core.Services;

var jwtInspector = new JwtInspectorService();
string token = "<your-jwt-token>";
var claims = jwtInspector.GetClaims(token);
foreach (var claim in claims)
{
    Console.WriteLine($"{claim.Key}: {claim.Value}");
}
```

### Example Usage: Validating a Token with HMAC-SHA256

```csharp
using JwtInspector.Core.Services;
using Microsoft.IdentityModel.Tokens;

var jwtInspector = new JwtInspectorService();
string secretKey = "my_secret_key_123456789123456789"; // 32 bytes key
string token = "<your-jwt-token>";
bool isValid = jwtInspector.ValidateToken(token, secretKey);
Console.WriteLine($"Is token valid: {isValid}");
```

## Methods Overview

### 🔎 Decoding Methods
- **DecodeBase64Url(string input)** → Decodes a Base64Url encoded string into plain text.  
- **DecodePayload(string token)** → Decodes the raw payload of a JWT without deserialization.  
- **DecodePayloadAsJson(string token)** → Returns the decoded JWT payload as a JSON string.  
- **DecodePayloadAs<T>(string token)** → Deserializes the JWT payload into a strongly typed object.  
- **ExtractJwtParts(string token)** → Splits the JWT into header, payload, and signature parts.  
- **GetAudience(string token)** → Retrieves the audience (`aud`) claim, returns `string.Empty` if not available.  
- **GetIssuer(string token)** → Retrieves the issuer (`iss`) claim, returns `string.Empty` if not available.  
- **GetJwtId(string token)** → Retrieves the JWT ID (`jti`) claim, returns `string.Empty` if not available.  
- **GetClaims(string token)** → Extracts all claims as a dictionary from the JWT payload.  
- **GetAllHeaders(string token)** → Retrieves all header values as a dictionary.  
- **GetExpirationDate(string token)** → Extracts the expiration (`exp`) as a `DateTime?`.  
- **GetIssuedAt(string token)** → Extracts the issued-at (`iat`) as a `DateTime?`.  
- **GetSigningAlgorithm(string token)** → Returns the signing algorithm (`alg`) defined in the JWT header.  
- **GetCustomClaim(string token, string claimKey)** → Returns a specific custom claim value by key.  
- **GetTokenSummary(string token)** → Builds a formatted JSON summary with header, payload, and signature presence.  
- **IsValidFormat(string token)** → Checks whether the JWT structure has three parts separated by dots.  
- **IsExpired(string token)** → Checks whether the JWT is expired based on the `exp` claim.  

### ✅ Validation Methods
- **ValidateToken(string token, string secretKey)** → Validates token signature and expiration using an HMAC-SHA secret key.  
- **ValidateIssuerAndAudience(string token, string expectedIssuer, string expectedAudience)** → Validates that issuer and audience match the expected values.  
- **VerifyIssuer(string token, string expectedIssuer)** → Validates that the token was issued by the expected issuer.  
- **ValidateLifetime(string token)** → Validates the token’s lifetime based on `exp` and `iat`.  
- **ValidateNotBefore(string token, TimeSpan? clockSkew = null)** → Validates that the token is not used before its `nbf` claim, optionally allowing clock skew.  
- **ValidateAlgorithm(string token, string expectedAlgorithm)** → Ensures that the JWT is signed with the expected algorithm.  
- **ValidateIssuerSigningKey(string token, SecurityKey key)** → Validates the token using a specific signing key.  
- **ValidateClaims(string token, IDictionary<string, string> requiredClaims)** → Ensures that the JWT contains all required claims with matching values.  

## JWT Format

A valid JWT token consists of three parts:

- **Header**: Contains metadata such as the signing algorithm (`alg`) and token type (`typ`).
- **Payload**: Contains the claims, which can be public, private, or registered claims such as `sub`, `iat`, `exp`, `aud`.
- **Signature**: A cryptographic signature used to verify the integrity of the token.

A JWT token is typically represented in the following format: `header.payload.signature`

## Example JWT

A typical JWT might look like this:

`eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U`

## Contributing
Thank you for considering to help out with the source code!
If you'd like to contribute, please fork, fix, commit and send a pull request for the maintainers to review and merge into the main code base.

 * [Setting up Git](https://docs.github.com/en/get-started/getting-started-with-git/set-up-git)
 * [Fork the repository](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo)
 * [Open an issue](https://github.com/engineering87/jwt-inspector/issues) if you encounter a bug or have a suggestion for improvements/features

## Licensee
JwtInspector source code is available under MIT License, see license in the source.

## Contact
Please contact at francesco.delre.87[at]gmail.com for any details.

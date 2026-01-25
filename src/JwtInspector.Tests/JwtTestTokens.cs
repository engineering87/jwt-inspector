// (c) 2024-2026 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtInspector.Tests;

internal static class JwtTestTokens
{
    internal static string CreateSymmetric(
        string secret,
        string? issuer = null,
        string? audience = null,
        DateTime? notBefore = null,
        DateTime? expires = null,
        string algorithm = SecurityAlgorithms.HmacSha256,
        IEnumerable<Claim>? extraClaims = null)
    {
        secret = EnsureMinBytes(secret, 32);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, algorithm);

        var now = DateTime.UtcNow;
        var nbf = notBefore ?? now.AddSeconds(-5);
        var exp = expires ?? now.AddMinutes(5);
        if (nbf >= exp) nbf = exp.AddSeconds(-5);
        var iat = nbf.AddSeconds(-1);

        var claims = new List<Claim>
        {
            new("sub", "123"),
            new("name", "John Doe"),
        };

        if (extraClaims is not null) claims.AddRange(extraClaims);

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateJwtSecurityToken(
            issuer: issuer,
            audience: audience,
            subject: new ClaimsIdentity(claims),
            notBefore: nbf,
            expires: exp,
            issuedAt: iat,
            signingCredentials: creds);

        return handler.WriteToken(token);
    }

    internal static string CreateAlgNoneToken(string headerJson, string payloadJson)
    {
        var header = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));
        var payload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));
        return $"{header}.{payload}.";
    }

    private static string EnsureMinBytes(string secret, int minBytes)
    {
        if (Encoding.UTF8.GetByteCount(secret) >= minBytes) return secret;

        var sb = new StringBuilder(secret);
        while (Encoding.UTF8.GetByteCount(sb.ToString()) < minBytes)
            sb.Append('_');

        return sb.ToString();
    }
}
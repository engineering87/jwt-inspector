// (c) 2024-2026 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using JwtInspector.Core.Exceptions;
using JwtInspector.Core.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace JwtInspector.Tests;

public sealed class JwtInspectorTests : IClassFixture<JwtInspectorFixture>
{
    private readonly IJwtInspector _jwt;
    public JwtInspectorTests(JwtInspectorFixture fx) => _jwt = fx.Inspector;

    [Fact]
    public void ExtractJwtParts_ShouldReturnThreeParts_ForValidToken()
    {
        var token = JwtTestTokens.CreateSymmetric("secret_for_parts_1234567890");
        var (h, p, s) = _jwt.ExtractJwtParts(token);

        Assert.False(string.IsNullOrWhiteSpace(h));
        Assert.False(string.IsNullOrWhiteSpace(p));
        Assert.False(string.IsNullOrWhiteSpace(s));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsValidFormat_ShouldReturnFalse_ForNullOrWhitespace(string? token)
    {
        Assert.False(_jwt.IsValidFormat(token ?? string.Empty));
    }

    [Fact]
    public void ExtractJwtParts_ShouldThrow_ForMalformedToken()
    {
        Assert.Throws<JwtInspectorException>(() => _jwt.ExtractJwtParts("MalformedTokenWithoutThreeParts"));
    }

    [Fact]
    public void DecodePayload_ShouldContainExpectedClaims()
    {
        var token = JwtTestTokens.CreateSymmetric(
            "secret_claims_1234567890",
            extraClaims: new[] { new System.Security.Claims.Claim("role", "admin") });

        var payload = _jwt.DecodePayload(token);

        Assert.Equal("123", payload["sub"]?.ToString());
        Assert.Equal("John Doe", payload["name"]?.ToString());
        Assert.Equal("admin", payload["role"]?.ToString());
        Assert.True(payload.ContainsKey("iat"));
    }

    [Fact]
    public void DecodePayload_ShouldPreserveNumericTypes_WhenPresent()
    {
        var token = JwtTestTokens.CreateSymmetric("secret_numeric_1234567890");
        var payload = _jwt.DecodePayload(token);

        Assert.True(payload.ContainsKey("iat"));
        Assert.IsNotType<string>(payload["iat"]);
    }

    [Fact]
    public void GetIssuerAudienceJwtId_ShouldReturnEmpty_WhenMissing()
    {
        // token senza issuer/audience/jti
        var token = JwtTestTokens.CreateSymmetric("secret_missing_meta_1234567890", issuer: null, audience: null);

        Assert.Equal(string.Empty, _jwt.GetIssuer(token));
        Assert.Equal(string.Empty, _jwt.GetAudience(token));
        Assert.Equal(string.Empty, _jwt.GetJwtId(token));
    }

    [Fact]
    public void GetAudience_ShouldReturnValue_WhenPresent()
    {
        var token = JwtTestTokens.CreateSymmetric("secret_aud_1234567890", audience: "my-audience");
        Assert.Equal("my-audience", _jwt.GetAudience(token));
    }

    [Fact]
    public void GetSigningAlgorithm_ShouldReturnHS256_ForSymmetricToken()
    {
        var token = JwtTestTokens.CreateSymmetric("secret_alg_1234567890", algorithm: SecurityAlgorithms.HmacSha256);
        Assert.Equal("HS256", _jwt.GetSigningAlgorithm(token));
    }

    [Fact]
    public void ValidateAlgorithm_ShouldRejectNone()
    {
        var token = JwtTestTokens.CreateAlgNoneToken(
            headerJson: "{\"alg\":\"none\",\"typ\":\"JWT\"}",
            payloadJson: "{\"sub\":\"123\"}");

        Assert.False(_jwt.ValidateAlgorithm(token, "HS256"));
    }

    [Fact]
    public void IsExpired_ShouldHonorClockSkew()
    {
        var token = JwtTestTokens.CreateSymmetric("secret_skew_1234567890", expires: DateTime.UtcNow.AddSeconds(-30));

        Assert.True(_jwt.IsExpired(token));
        Assert.False(_jwt.IsExpired(token, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void ValidateToken_ShouldReturnTrue_WithCorrectSecret()
    {
        var secret = "my_secret_key_123456789123456789";
        var token = JwtTestTokens.CreateSymmetric(secret, expires: DateTime.UtcNow.AddMinutes(10));

        Assert.True(_jwt.ValidateToken(token, secret));
    }

    [Fact]
    public void ValidateToken_ShouldReturnFalse_WithWrongSecret()
    {
        var secret = "correct_secret_1234567890123456";
        var token = JwtTestTokens.CreateSymmetric(secret, expires: DateTime.UtcNow.AddMinutes(10));

        Assert.False(_jwt.ValidateToken(token, "wrong_secret_1234567890123456"));
    }
}

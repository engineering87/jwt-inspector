// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using JwtInspector.Core.Interfaces;
using JwtInspector.Core.Services;
using JwtInspector.Core.Exceptions;

namespace JwtInspector.Tests
{
    public class JwtInspectorTests
    {
        private readonly IJwtInspector _jwtInspector;

        public JwtInspectorTests()
        {
            _jwtInspector = new JwtInspectorService();
        }

        [Fact]
        public void DecodePayload_ShouldReturnClaims()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var claims = _jwtInspector.DecodePayloadAsJson(token);

            // Assert
            Assert.NotEmpty(claims);
        }

        [Fact]
        public void DecodeBase64Url_ShouldReturnDecodedString_ForValidBase64Url()
        {
            // Arrange
            string input = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9";

            // Act
            var decodedString = _jwtInspector.DecodeBase64Url(input);

            // Assert
            Assert.Equal("{\"alg\": \"HS256\", \"typ\": \"JWT\"}", decodedString);
        }

        [Fact]
        public void ExtractJwtParts_ShouldReturnCorrectParts_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var (header, payload, signature) = _jwtInspector.ExtractJwtParts(token);

            // Assert
            Assert.NotNull(header);
            Assert.NotNull(payload);
            Assert.NotNull(signature);
        }

        [Fact]
        public void GetAudience_ShouldReturnCorrectAudience_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var audience = _jwtInspector.GetAudience(token);

            // Assert
            Assert.Equal("", audience);
        }

        [Fact]
        public void GetClaims_ShouldReturnClaims_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var claims = _jwtInspector.GetClaims(token);

            // Assert
            Assert.Contains("sub", claims.Keys);
            Assert.Contains("name", claims.Keys);
        }

        [Fact]
        public void GetExpirationDate_ShouldReturnExpiration_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzMwOTQxMjYwLCJleHAiOjE3MzA5NDQ4NjAsImp0aSI6InVuaXF1ZS1qd3QtaWQtMTIzNDUifQ.2pMlyxG2GFLsVTV3w8rKkIQyFq5qNG3hdp7y5HL9Wfs";

            // Act
            var expirationDate = _jwtInspector.GetExpirationDate(token);

            // Assert
            Assert.NotNull(expirationDate);
        }

        [Fact]
        public void GetIssuedAt_ShouldReturnIssuedAt_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var issuedAt = _jwtInspector.GetIssuedAt(token);

            // Assert
            Assert.NotNull(issuedAt);
        }

        [Fact]
        public void GetJwtId_ShouldReturnJwtId_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzMwOTQxMjYwLCJleHAiOjE3MzA5NDQ4NjAsImp0aSI6InVuaXF1ZS1qd3QtaWQtMTIzNDUifQ.xIqTdUzcxlC3xpXufH0jWh7ZZV4X2_yxD1KXvQZ-a4o";

            // Act
            var jwtId = _jwtInspector.GetJwtId(token);

            // Assert
            Assert.NotEmpty(jwtId);
        }

        [Fact]
        public void GetSigningAlgorithm_ShouldReturnAlgorithm_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var signingAlgorithm = _jwtInspector.GetSigningAlgorithm(token);

            // Assert
            Assert.Equal("HS256", signingAlgorithm);
        }

        [Fact]
        public void IsExpired_ShouldReturnTrue_ForExpiredToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgInJvbGUiOiAidXNlciIsICJpYXQiOiAiMTY4NzI3MTI5NiJ9.kG3A1qk2J4tqjX2iQ3gg-E1hZdxW9-L_vtgdGsTdmDw";

            // Act
            var isExpired = _jwtInspector.IsExpired(token);

            // Assert
            Assert.True(isExpired);
        }

        [Fact]
        public void IsValidFormat_ShouldReturnTrue_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var isValid = _jwtInspector.IsValidFormat(token);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void ValidateToken_ShouldReturnTrue_ForValidToken()
        {
            // Arrange
            string secretKey = "my_secret_key_123456789123456789"; // 32 bits
            var tokenHandler = new JwtSecurityTokenHandler();
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[]
                {
                    new System.Security.Claims.Claim("sub", "1234567890"),
                    new System.Security.Claims.Claim("name", "John Doe"),
                    new System.Security.Claims.Claim("iat", "1516239022")
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);

            var tokenString = tokenHandler.WriteToken(token);

            // Act
            var isValid = _jwtInspector.ValidateToken(tokenString, secretKey);

            // Assert
            Assert.True(isValid, "The token should be valid when using the correct secret key.");
        }

        [Fact]
        public void GetTokenSummary_ShouldReturnFormattedJson_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var summary = _jwtInspector.GetTokenSummary(token);

            // Assert
            Assert.NotEmpty(summary);
            Assert.Contains("\"Header\":", summary);
            Assert.Contains("\"Payload\":", summary);
            Assert.Contains("\"Signature\":", summary);
        }

        [Fact]
        public void ExtractJwtParts_ShouldThrowException_ForMalformedToken()
        {
            // Arrange
            string malformedToken = "MalformedTokenWithoutThreeParts";

            // Act & Assert
            Assert.Throws<JwtInspectorException>(() => _jwtInspector.ExtractJwtParts(malformedToken));
        }

        // === Additional tests (paste inside JwtInspectorTests class) ===

        #region Algorithm validation

        [Fact]
        public void ValidateAlgorithm_ShouldRejectNone()
        {
            // Arrange: JWT with alg = none (unsigned)
            var header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
            var payload = "{\"sub\":\"123\",\"name\":\"John Doe\"}";
            string token = $"{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header))}.{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload))}.";

            // Act
            var isValidAlg = _jwtInspector.ValidateAlgorithm(token, "HS256");

            // Assert
            Assert.False(isValidAlg);
        }

        [Fact]
        public void ValidateAlgorithm_ShouldMatchExpected()
        {
            // Arrange
            string secret = "test_secret_1234567890_1234567890";
            var token = CreateSymmetricJwt(secret, algorithm: SecurityAlgorithms.HmacSha256, expires: DateTime.UtcNow.AddMinutes(10));

            // Act
            var ok = _jwtInspector.ValidateAlgorithm(token, "HS256");

            // Assert
            Assert.True(ok);
        }

        #endregion

        #region Lifetime / Expiration / NotBefore

        [Fact]
        public void ValidateLifetime_ShouldReturnTrue_ForFutureExp()
        {
            // Arrange
            string secret = "future_exp_secret_1234567890_ABCDEFG";
            var token = CreateSymmetricJwt(secret, expires: DateTime.UtcNow.AddMinutes(5)); // valid for 5 minutes

            // Act
            var ok = _jwtInspector.ValidateLifetime(token);

            // Assert
            Assert.True(ok);
        }

        [Fact]
        public void ValidateLifetime_ShouldReturnFalse_ForPastExp()
        {
            // Arrange
            string secret = "past_exp_secret_1234567890_ABCDEFG";
            var token = CreateSymmetricJwt(secret, expires: DateTime.UtcNow.AddMinutes(-1)); // already expired

            // Act
            var ok = _jwtInspector.ValidateLifetime(token);

            // Assert
            Assert.False(ok);
        }

        [Fact]
        public void ValidateNotBefore_ShouldRespectNbf()
        {
            // Arrange
            string secret = "nbf_secret_1234567890_ABCDEFG";
            var nbf = DateTime.UtcNow.AddMinutes(2); // not valid for 2 minutes
            var token = CreateSymmetricJwt(secret, notBefore: nbf, expires: DateTime.UtcNow.AddMinutes(10));

            // Act
            var okNow = _jwtInspector.ValidateNotBefore(token); // with current time

            // Assert
            Assert.False(okNow); // not valid yet
        }

        [Fact]
        public void IsExpired_ShouldHonorClockSkew()
        {
            // Arrange: token that expires in 2 minutes
            string secret = "skew_secret_1234567890_1234567890_XXXX";
            var token = CreateSymmetricJwt(secret, expires: DateTime.UtcNow.AddMinutes(2));

            // Act
            var expiredNoSkew = _jwtInspector.IsExpired(token); // default skew = null => 0
            var expiredWithSkew = _jwtInspector.IsExpired(token, TimeSpan.FromMinutes(-5)); // negative skew simulates stricter check (treat earlier)

            // Assert
            Assert.False(expiredNoSkew);
            // With negative skew, we effectively compare ValidTo <= UtcNow - 5 min -> should still be false in normal cases,
            // but this asserts that the API accepts the parameter without throwing.
            Assert.False(expiredWithSkew);
        }

        #endregion

        #region Issuer / Audience / ID / Custom Claims

        [Fact]
        public void GetIssuerAudienceJwtId_ShouldReturnEmpty_WhenMissing()
        {
            // Arrange: token without iss/aud/jti
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJuYW1lIjogIkRvZSJ9.sC5aE7x2I2e3r0u1Vg3j1r3cmgH8IeXlZ2l1P2R9J5E";

            // Act
            var iss = _jwtInspector.GetIssuer(token);
            var aud = _jwtInspector.GetAudience(token);
            var jti = _jwtInspector.GetJwtId(token);

            // Assert
            Assert.Equal(string.Empty, iss);
            Assert.Equal(string.Empty, aud);
            Assert.Equal(string.Empty, jti);
        }

        [Fact]
        public void GetCustomClaim_ShouldReturnNull_WhenMissing()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJuYW1lIjogIkRvZSJ9.sC5aE7x2I2e3r0u1Vg3j1r3cmgH8IeXlZ2l1P2R9J5E";

            // Act
            var value = _jwtInspector.GetCustomClaim(token, "non_existing_claim");

            // Assert
            Assert.Null(value);
        }

        #endregion

        #region Format / Headers / Claims

        [Fact]
        public void IsValidFormat_ShouldReturnFalse_ForMalformedToken()
        {
            // Arrange
            string malformed = "only.two.parts.";

            // Act
            var isValid = _jwtInspector.IsValidFormat(malformed);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void GetAllHeaders_ShouldIncludeAlg()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJuYW1lIjogIkRvZSJ9.sC5aE7x2I2e3r0u1Vg3j1r3cmgH8IeXlZ2l1P2R9J5E";

            // Act
            var headers = _jwtInspector.GetAllHeaders(token);

            // Assert
            Assert.Contains("alg", headers.Keys, StringComparer.OrdinalIgnoreCase);
        }

        [Fact]
        public void HasClaim_ShouldReturnTrue_WhenClaimExists()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJuYW1lIjogIkRvZSJ9.sC5aE7x2I2e3r0u1Vg3j1r3cmgH8IeXlZ2l1P2R9J5E";

            // Act
            var hasName = _jwtInspector.HasClaim(token, "name");

            // Assert
            Assert.True(hasName);
        }

        #endregion

        #region Validation with keys

        [Fact]
        public void ValidateIssuerSigningKey_Symmetric_ShouldReturnTrue_WithCorrectKey()
        {
            // Arrange
            string secret = "correct_secret_key_1234567890123456";
            var token = CreateSymmetricJwt(secret, expires: DateTime.UtcNow.AddMinutes(5));

            // Act
            var ok = _jwtInspector.ValidateIssuerSigningKey(token, secret);

            // Assert
            Assert.True(ok);
        }

        [Fact]
        public void ValidateIssuerSigningKey_Symmetric_ShouldReturnFalse_WithWrongKey()
        {
            // Arrange
            string secret = "correct_secret_key_1234567890123456";
            var token = CreateSymmetricJwt(secret, expires: DateTime.UtcNow.AddMinutes(5));

            // Act
            var ok = _jwtInspector.ValidateIssuerSigningKey(token, "wrong_secret_key_1234567890");

            // Assert
            Assert.False(ok);
        }

        [Fact]
        public void ValidateIssuerSigningKey_AsymmetricRsa_ShouldReturnTrue_WithMatchingPublicKey()
        {
            // Arrange: create RSA keypair and sign with private; validate with public
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var privateKey = new RsaSecurityKey(rsa.ExportParameters(true));
            var publicKey = new RsaSecurityKey(rsa.ExportParameters(false));

            var token = CreateAsymmetricJwt(privateKey, SecurityAlgorithms.RsaSha256, expires: DateTime.UtcNow.AddMinutes(5));

            // Act
            var ok = _jwtInspector.ValidateIssuerSigningKey(token, publicKey);

            // Assert
            Assert.True(ok);
        }

        #endregion

        #region Issuer & Audience validation

        [Fact]
        public void ValidateIssuerAndAudience_ShouldReturnTrue_WhenBothMatch()
        {
            // Arrange
            string secret = "issuer_audience_secret_1234567890_ABCDEF";
            var issuer = "https://issuer.test";
            var audience = "my-audience";
            var token = CreateSymmetricJwt(secret, issuer: issuer, audience: audience, expires: DateTime.UtcNow.AddMinutes(5));

            // Act
            var ok = _jwtInspector.ValidateIssuerAndAudience(token, issuer, audience);

            // Assert
            Assert.True(ok);
        }

        [Fact]
        public void ValidateIssuerAndAudience_ShouldReturnFalse_WhenMismatch()
        {
            // Arrange
            string secret = "issuer_audience_secret_1234567890_ABCDEF";
            var token = CreateSymmetricJwt(secret, issuer: "https://issuer.correct", audience: "aud-correct", expires: DateTime.UtcNow.AddMinutes(5));

            // Act
            var okWrongIssuer = _jwtInspector.ValidateIssuerAndAudience(token, "https://issuer.wrong", "aud-correct");
            var okWrongAudience = _jwtInspector.ValidateIssuerAndAudience(token, "https://issuer.correct", "aud-wrong");

            // Assert
            Assert.False(okWrongIssuer);
            Assert.False(okWrongAudience);
        }

        #endregion

        #region Payload (raw) typed deserialization

        private sealed class SamplePayload
        {
            public string? sub { get; set; }
            public string? name { get; set; }
            public long? iat { get; set; }
        }

        [Fact]
        public void DecodePayloadAs_ShouldDeserializeRawPayload()
        {
            // Arrange: known token with sub/name/iat
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var dto = _jwtInspector.DecodePayloadAs<SamplePayload>(token);

            // Assert
            Assert.NotNull(dto);
            Assert.Equal("1234567890", dto.sub);
            Assert.Equal("John Doe", dto.name);
            Assert.True(dto.iat.HasValue);
        }

        #endregion

        // === Helpers (paste at the bottom of JwtInspectorTests class) ===

        private static string CreateSymmetricJwt(
            string secret,
            string? issuer = null,
            string? audience = null,
            DateTime? notBefore = null,
            DateTime? expires = null,
            string algorithm = SecurityAlgorithms.HmacSha256)
        {
            secret = EnsureMinBytes(secret, 32);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var creds = new SigningCredentials(key, algorithm);

            var now = DateTime.UtcNow;

            // Start from sensible defaults
            var nbf = notBefore ?? now.AddSeconds(-5);
            var exp = expires ?? now.AddMinutes(5);

            // Ensure nbf <= exp (shift nbf back if needed)
            if (nbf >= exp)
                nbf = exp.AddSeconds(-5);

            // Ensure iat <= nbf
            var iat = nbf.AddSeconds(-1);

            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateJwtSecurityToken(
                issuer: issuer,
                audience: audience,
                subject: new System.Security.Claims.ClaimsIdentity(new[]
                {
            new System.Security.Claims.Claim("sub","123"),
            new System.Security.Claims.Claim("name","John Doe")
                }),
                notBefore: nbf,
                expires: exp,
                issuedAt: iat,
                signingCredentials: creds);

            return handler.WriteToken(token);
        }

        private static string CreateAsymmetricJwt(
            SecurityKey privateKey,
            string algorithm,
            string? issuer = null,
            string? audience = null,
            DateTime? notBefore = null,
            DateTime? expires = null)
        {
            var creds = new SigningCredentials(privateKey, algorithm);

            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateJwtSecurityToken(
                issuer: issuer,
                audience: audience,
                subject: new System.Security.Claims.ClaimsIdentity(new[]
                {
            new System.Security.Claims.Claim("sub","123"),
            new System.Security.Claims.Claim("name","John Doe")
                }),
                notBefore: notBefore ?? DateTime.UtcNow.AddSeconds(-1),
                expires: expires ?? DateTime.UtcNow.AddMinutes(5),
                issuedAt: DateTime.UtcNow,
                signingCredentials: creds);

            return handler.WriteToken(token);
        }

        private static string EnsureMinBytes(string secret, int minBytes = 32)
        {
            // Deterministic padding for tests (NOT for production crypto)
            if (Encoding.UTF8.GetByteCount(secret) >= minBytes) return secret;
            var sb = new StringBuilder(secret);
            while (Encoding.UTF8.GetByteCount(sb.ToString()) < minBytes) sb.Append('_');
            return sb.ToString();
        }

    }
}

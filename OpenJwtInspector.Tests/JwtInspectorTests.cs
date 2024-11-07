// (c) 2022 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens;
using OpenJwtInspector.Interfaces;
using OpenJwtInspector.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace OpenJwtInspector.Tests
{
    public class JwtInspectorTests
    {
        private readonly IJwtDecoder _jwtDecoder;
        private readonly IJwtValidator _jwtValidator;

        public JwtInspectorTests()
        {
            _jwtDecoder = new JwtDecoderService();
            _jwtValidator = new JwtValidatorService();
        }

        [Fact]
        public void DecodePayload_ShouldReturnClaims()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var claims = _jwtDecoder.DecodePayloadAsJson(token);

            // Assert
            Assert.NotEmpty(claims);
        }

        [Fact]
        public void DecodeBase64Url_ShouldReturnDecodedString_ForValidBase64Url()
        {
            // Arrange
            string input = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9";

            // Act
            var decodedString = _jwtDecoder.DecodeBase64Url(input);

            // Assert
            Assert.Equal("{\"alg\": \"HS256\", \"typ\": \"JWT\"}", decodedString);
        }

        [Fact]
        public void ExtractJwtParts_ShouldReturnCorrectParts_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var (header, payload, signature) = _jwtDecoder.ExtractJwtParts(token);

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
            var audience = _jwtDecoder.GetAudience(token);

            // Assert
            Assert.Equal("", audience);
        }

        [Fact]
        public void GetClaims_ShouldReturnClaims_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var claims = _jwtDecoder.GetClaims(token);

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
            var expirationDate = _jwtDecoder.GetExpirationDate(token);

            // Assert
            Assert.NotNull(expirationDate);
        }

        [Fact]
        public void GetIssuedAt_ShouldReturnIssuedAt_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var issuedAt = _jwtDecoder.GetIssuedAt(token);

            // Assert
            Assert.NotNull(issuedAt);
        }

        [Fact]
        public void GetJwtId_ShouldReturnJwtId_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzMwOTQxMjYwLCJleHAiOjE3MzA5NDQ4NjAsImp0aSI6InVuaXF1ZS1qd3QtaWQtMTIzNDUifQ.xIqTdUzcxlC3xpXufH0jWh7ZZV4X2_yxD1KXvQZ-a4o";

            // Act
            var jwtId = _jwtDecoder.GetJwtId(token);

            // Assert
            Assert.NotEmpty(jwtId);
        }

        [Fact]
        public void GetSigningAlgorithm_ShouldReturnAlgorithm_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var signingAlgorithm = _jwtDecoder.GetSigningAlgorithm(token);

            // Assert
            Assert.Equal("HS256", signingAlgorithm);
        }

        [Fact]
        public void IsExpired_ShouldReturnTrue_ForExpiredToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgInJvbGUiOiAidXNlciIsICJpYXQiOiAiMTY4NzI3MTI5NiJ9.kG3A1qk2J4tqjX2iQ3gg-E1hZdxW9-L_vtgdGsTdmDw";

            // Act
            var isExpired = _jwtDecoder.IsExpired(token);

            // Assert
            Assert.True(isExpired);
        }

        [Fact]
        public void IsValidFormat_ShouldReturnTrue_ForValidToken()
        {
            // Arrange
            string token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.MD8fpgF7N0XWhQGGVm9lA_EvVoHkcmrr74xhL2y7H3U";

            // Act
            var isValid = _jwtDecoder.IsValidFormat(token);

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
            var isValid = _jwtValidator.ValidateToken(tokenString, secretKey);

            // Assert
            Assert.True(isValid, "The token should be valid when using the correct secret key.");
        }
    }
}

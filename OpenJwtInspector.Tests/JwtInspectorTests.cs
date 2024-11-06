// (c) 2022 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)using Microsoft.IdentityModel.Tokens;
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
        public void ValidateToken_ShouldReturnTrue_ForValidToken()
        {
            string secretKey = "my_secret_key_12345";

            // Convert the secret key string to a byte array
            byte[] keyBytes = Encoding.ASCII.GetBytes(secretKey);

            // If the key is shorter than 256 bits, pad it to 256 bits (32 bytes)
            byte[] key256Bits = new byte[32];
            Array.Copy(keyBytes, key256Bits, Math.Min(keyBytes.Length, 32));

            // Step 2: Generate a valid JWT token for testing using the corrected key size
            var tokenHandler = new JwtSecurityTokenHandler();
            var signingKey = new SymmetricSecurityKey(key256Bits); // Use the padded key

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

            var encondedSecretKey = Encoding.UTF8.GetString(keyBytes);
            var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            token.Header.Add("kid", encondedSecretKey);

            var tokenString = tokenHandler.WriteToken(token);

            // Step 3: Use JwtValidator to validate the token
            var isValid = _jwtValidator.ValidateToken(tokenString, encondedSecretKey);

            // Step 4: Assert that the token is valid
            Assert.True(isValid, "The token should be valid when using the correct secret key.");
        }
    }
}

// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using Microsoft.IdentityModel.Tokens;
using JwtInspector.Core.Exceptions;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using JwtInspector.Core.Interfaces;

namespace JwtInspector.Core.Services
{
    /// <summary>
    /// Service to validate JWT tokens.
    /// </summary>
    public class JwtValidatorService : IJwtValidator
    {
        private static readonly JwtSecurityTokenHandler _tokenHandler = new JwtSecurityTokenHandler();

        /// <inheritdoc />
        public bool ValidateToken(string token, string secretKey)
        {
            var key = Encoding.UTF8.GetBytes(secretKey);

            try
            {
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                };

                _tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                return validatedToken != null;
            }
            catch (SecurityTokenExpiredException)
            {
                throw new JwtInspectorException("The token has expired.");
            }
            catch (SecurityTokenException ex)
            {
                throw new JwtInspectorException("Invalid JWT token.", ex);
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("An error occurred while decoding the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public bool VerifyIssuer(string token, string expectedIssuer)
        {
            var jwtToken = _tokenHandler.ReadJwtToken(token);

            return string.Equals(
                jwtToken.Issuer?.Trim(),
                expectedIssuer?.Trim(),
                StringComparison.OrdinalIgnoreCase
            );
        }

        /// <inheritdoc />
        public bool ValidateIssuerAndAudience(string token, string expectedIssuer, string expectedAudience)
        {
            try
            {
                _tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = expectedIssuer,
                    ValidAudience = expectedAudience,
                    ValidateIssuerSigningKey = false,
                    ValidateLifetime = false
                }, out _);

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <inheritdoc />
        public bool ValidateLifetime(string token)
        {
            var jwtToken = _tokenHandler.ReadJwtToken(token);

            return jwtToken.ValidTo > DateTime.UtcNow;
        }

        /// <inheritdoc />
        public bool ValidateAlgorithm(string token, string expectedAlgorithm)
        {
            var jwtToken = _tokenHandler.ReadJwtToken(token);

            var supportedAlgorithms = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "HS256", SecurityAlgorithms.HmacSha256 },
                { "HS384", SecurityAlgorithms.HmacSha384 },
                { "HS512", SecurityAlgorithms.HmacSha512 },
                { "RS256", SecurityAlgorithms.RsaSha256 },
                { "RS384", SecurityAlgorithms.RsaSha384 },
                { "RS512", SecurityAlgorithms.RsaSha512 },
                { "PS256", SecurityAlgorithms.RsaSsaPssSha256 },
                { "PS384", SecurityAlgorithms.RsaSsaPssSha384 },
                { "PS512", SecurityAlgorithms.RsaSsaPssSha512 },
                { "ES256", SecurityAlgorithms.EcdsaSha256 },
                { "ES384", SecurityAlgorithms.EcdsaSha384 },
                { "ES512", SecurityAlgorithms.EcdsaSha512 },
                { "A128KW", SecurityAlgorithms.Aes128KW },
                { "A192KW", SecurityAlgorithms.Aes192KW },
                { "A256KW", SecurityAlgorithms.Aes256KW },
                { "A128GCM", SecurityAlgorithms.Aes128Gcm },
                { "A192GCM", SecurityAlgorithms.Aes192Gcm },
                { "A256GCM", SecurityAlgorithms.Aes256Gcm },
                { "AES256CBCHMACSHA512 ", SecurityAlgorithms.Aes256CbcHmacSha512 }
            };

            return supportedAlgorithms.TryGetValue(expectedAlgorithm, out var mappedAlgorithm)
                      && string.Equals(jwtToken.Header.Alg, mappedAlgorithm, StringComparison.OrdinalIgnoreCase);
        }

        /// <inheritdoc />
        public bool ValidateIssuerSigningKey(string token, string signingKey)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            try
            {
                _tokenHandler.ValidateToken(token, validationParameters, out _);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <inheritdoc />
        public bool ValidateClaims(string token, IDictionary<string, string> requiredClaims)
        {
            var jwtToken = _tokenHandler.ReadJwtToken(token);

            foreach (var claim in requiredClaims)
            {
                var tokenClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == claim.Key);
                if (tokenClaim == null || tokenClaim.Value != claim.Value)
                    return false;
            }
            return true;
        }

        /// <inheritdoc />
        public bool ValidateNotBefore(string token)
        {
            var jwtToken = _tokenHandler.ReadJwtToken(token);

            return jwtToken.ValidFrom <= DateTime.UtcNow;
        }
    }
}

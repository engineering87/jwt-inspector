// (c) 2022 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using Microsoft.IdentityModel.Tokens;
using OpenJwtInspector.Exceptions;
using OpenJwtInspector.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace OpenJwtInspector.Services
{
    /// <summary>
    /// Service to validate JWT tokens.
    /// </summary>
    public class JwtValidatorService : IJwtValidator
    {
        /// <inheritdoc />
        public bool ValidateToken(string token, string secretKey)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(secretKey);

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return validatedToken != null;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("An error occurred while decoding the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public DateTime? GetExpirationDate(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            return jwtToken.ValidTo == DateTime.MinValue ? (DateTime?)null : jwtToken.ValidTo;
        }

        public bool VerifyIssuer(string token, string expectedIssuer)
        {
            throw new NotImplementedException();
        }

        public bool ValidateIssuerAndAudience(string token, string expectedIssuer, string expectedAudience)
        {
            throw new NotImplementedException();
        }

        public bool ValidateLifetime(string token)
        {
            throw new NotImplementedException();
        }

        public bool ValidateAlgorithm(string token, string expectedAlgorithm)
        {
            throw new NotImplementedException();
        }
    }
}

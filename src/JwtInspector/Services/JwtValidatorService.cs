// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using Microsoft.IdentityModel.Tokens;
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
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var p = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero,
                ValidateLifetime = true
            };

            try
            {
                _tokenHandler.ValidateToken(token, p, out _);
                return true;
            }
            catch (SecurityTokenException)
            {
                return false;
            }
        }

        /// <inheritdoc />
        public bool ValidateIssuerSigningKey(string token, SecurityKey key)
        {
            var p = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            try 
            { 
                _tokenHandler.ValidateToken(token, p, out _); 
                return true; 
            }
            catch 
            { 
                return false; 
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
                var jwt = _tokenHandler.ReadJwtToken(token);

                var issuerOk = string.Equals(
                    jwt.Issuer?.Trim(),
                    expectedIssuer?.Trim(),
                    StringComparison.OrdinalIgnoreCase);

                // audience can be multi-valued; match any
                var audienceOk = jwt.Audiences.Any(a =>
                    string.Equals(a?.Trim(), expectedAudience?.Trim(), StringComparison.OrdinalIgnoreCase));

                return issuerOk && audienceOk;
            }
            catch
            {
                return false;
            }
        }

        /// <inheritdoc />
        public bool ValidateLifetime(string token)
        {
            try
            {
                var jwt = _tokenHandler.ReadJwtToken(token);
                var now = DateTime.UtcNow;

                // If 'nbf' is present, require now >= nbf
                if (jwt.ValidFrom != DateTime.MinValue && now < jwt.ValidFrom)
                    return false;

                // If 'exp' is present, require now < exp
                if (jwt.ValidTo != DateTime.MinValue && now >= jwt.ValidTo)
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <inheritdoc />
        public bool ValidateAlgorithm(string token, string expectedAlgorithm)
        {
            var jwt = _tokenHandler.ReadJwtToken(token);
            if (string.Equals(jwt.Header.Alg, "none", StringComparison.OrdinalIgnoreCase))
                return false; // hard-fail: unsigned tokens

            return string.Equals(jwt.Header.Alg?.Trim(), expectedAlgorithm?.Trim(), StringComparison.OrdinalIgnoreCase);
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
        public bool ValidateNotBefore(string token, TimeSpan? clockSkew = null)
        {
            try
            {
                var jwtToken = _tokenHandler.ReadJwtToken(token);
                var skew = clockSkew ?? TimeSpan.Zero;

                // If no nbf provided, treat as valid
                if (jwtToken.ValidFrom == DateTime.MinValue)
                    return true;

                // Now must be >= (nbf - skew)
                return DateTime.UtcNow >= jwtToken.ValidFrom.Subtract(skew);
            }
            catch
            {
                return false;
            }
        }
    }
}

// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using JwtInspector.Core.Interfaces;
using JwtInspector.Core.Exceptions;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;

namespace JwtInspector.Core.Services
{
    /// <summary>
    /// Service to decode JWT tokens.
    /// </summary>
    public class JwtDecoderService : IJwtDecoder
    {
        /// <inheritdoc />
        public string DecodeBase64Url(string input)
        {
            try
            {
                string paddedInput = input.Length % 4 == 0 ? input : input + new string('=', 4 - input.Length % 4);
                byte[] bytes = Convert.FromBase64String(paddedInput.Replace('-', '+').Replace('_', '/'));
                return Encoding.UTF8.GetString(bytes);
            }
            catch (FormatException ex)
            {
                throw new JwtInspectorException("Invalid base64 URL encoding.", ex);
            }
        }

        /// <inheritdoc />
        public Dictionary<string, object> DecodePayload(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new JwtInspectorException("Invalid token format. Expected a standard JWT with three base64-encoded sections.");
            }

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                var payload = new Dictionary<string, object>();
                foreach (var claim in jwtToken.Claims)
                {
                    payload[claim.Type] = claim.Value;
                }

                return payload;
            }
            catch (ArgumentException ex)
            {
                throw new JwtInspectorException("Invalid JWT token format.", ex);
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("An error occurred while decoding the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public string DecodePayloadAsJson(string token)
        {
            try
            {
                var payload = DecodePayload(token);
                return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to serialize the payload as JSON.", ex);
            }
        }

        /// <inheritdoc />
        public (string Header, string Payload, string Signature) ExtractJwtParts(string token)
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                throw new JwtInspectorException("Invalid JWT format. A JWT token must have three parts separated by dots.");
            }

            try
            {
                string header = DecodeBase64Url(parts[0]);
                string payload = DecodeBase64Url(parts[1]);
                string signature = parts[2];

                return (header, payload, signature);
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to extract and decode JWT parts.", ex);
            }
        }

        /// <inheritdoc />
        public string GetAudience(string token)
        {
            try
            {
                var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
                return jwtToken.Audiences.FirstOrDefault() ?? string.Empty;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve the audience from the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public IDictionary<string, object> GetClaims(string token)
        {
            try
            {
                var claims = new Dictionary<string, object>();
                var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);

                foreach (var claim in jwtToken.Claims)
                {
                    claims[claim.Type] = claim.Value;
                }

                return claims;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve claims from the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public DateTime? GetExpirationDate(string token)
        {
            try
            {
                var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
                return jwtToken.ValidTo != DateTime.MinValue ? jwtToken.ValidTo : null;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve the expiration date from the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public DateTime? GetIssuedAt(string token)
        {
            try
            {
                var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
                return jwtToken.IssuedAt != DateTime.MinValue ? jwtToken.IssuedAt : null;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve the issued-at date from the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public string GetJwtId(string token)
        {
            try
            {
                var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
                return jwtToken.Id;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve the JWT ID from the token.", ex);
            }
        }

        /// <inheritdoc />
        public string GetSigningAlgorithm(string token)
        {
            try
            {
                var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
                return jwtToken.Header.Alg;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve the signing algorithm from the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public bool IsExpired(string token)
        {
            try
            {
                var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
                return jwtToken.ValidTo <= DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to determine if the JWT token is expired.", ex);
            }
        }

        /// <inheritdoc />
        public bool IsValidFormat(string token)
        {
            try
            {
                var parts = token.Split('.');
                return parts.Length == 3;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to verify the JWT token format.", ex);
            }
        }
    }
}


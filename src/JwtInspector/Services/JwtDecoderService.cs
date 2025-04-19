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
        private static readonly JwtSecurityTokenHandler _tokenHandler = new JwtSecurityTokenHandler();

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
                var jwtToken = _tokenHandler.ReadJwtToken(token);

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
        public T DecodePayloadAs<T>(string token) where T : class
        {
            try
            {
                string payloadJson = DecodePayloadAsJson(token);
                return JsonSerializer.Deserialize<T>(payloadJson, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                }) ?? throw new JwtInspectorException("Failed to deserialize payload as the specified type.");
            }
            catch (JsonException ex)
            {
                throw new JwtInspectorException("Failed to deserialize the payload to the specified type.", ex);
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("An error occurred while decoding the payload.", ex);
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
        public IDictionary<string, object> GetAllHeaders(string token)
        {
            try
            {
                var jwtToken = _tokenHandler.ReadJwtToken(token);
                var headers = new Dictionary<string, object>();

                foreach (var header in jwtToken.Header)
                {
                    headers[header.Key] = header.Value;
                }

                return headers;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve headers from the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public string GetAudience(string token)
        {
            try
            {
                var jwtToken = _tokenHandler.ReadJwtToken(token);
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
                var jwtToken = _tokenHandler.ReadJwtToken(token);

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
        public object GetCustomClaim(string token, string claimKey)
        {
            try
            {
                var claims = GetClaims(token);
                return claims.TryGetValue(claimKey, out var claimValue) ? claimValue : null;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException($"Failed to retrieve the custom claim '{claimKey}' from the JWT token.", ex);
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
                var jwtToken = _tokenHandler.ReadJwtToken(token);
                return jwtToken.IssuedAt != DateTime.MinValue ? jwtToken.IssuedAt : null;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve the issued-at date from the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public string GetIssuer(string token)
        {
            try
            {
                var jwtToken = _tokenHandler.ReadJwtToken(token);
                return jwtToken.Issuer ?? string.Empty;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve the issuer from the JWT token.", ex);
            }
        }


        /// <inheritdoc />
        public string GetJwtId(string token)
        {
            try
            {
                var jwtToken = _tokenHandler.ReadJwtToken(token);
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
                var jwtToken = _tokenHandler.ReadJwtToken(token);
                return jwtToken.Header.Alg;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve the signing algorithm from the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public string GetTokenSummary(string token)
        {
            try
            {
                var (header, payload, signature) = ExtractJwtParts(token);
                var headerData = JsonSerializer.Deserialize<Dictionary<string, object>>(header);
                var payloadData = JsonSerializer.Deserialize<Dictionary<string, object>>(payload);

                if (headerData == null || payloadData == null)
                {
                    throw new JwtInspectorException("Failed to parse header or payload.");
                }

                var summary = new
                {
                    Header = headerData,
                    Payload = payloadData,
                    Signature = signature
                };

                return JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true });
            }
            catch (JsonException ex)
            {
                throw new JwtInspectorException("Failed to parse header or payload as JSON.", ex);
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to generate the JWT summary.", ex);
            }
        }

        /// <inheritdoc />
        public bool IsExpired(string token)
        {
            try
            {
                var jwtToken = _tokenHandler.ReadJwtToken(token);
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

        /// <inheritdoc />
        public bool HasClaim(string token, string claimKey)
        {
            try
            {
                var jwtToken = _tokenHandler.ReadJwtToken(token);
                return jwtToken.Claims.Any(claim => claim.Type.Equals(claimKey, StringComparison.OrdinalIgnoreCase));
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException($"Failed to check existence of claim '{claimKey}' in the JWT token.", ex);
            }
        }
    }
}


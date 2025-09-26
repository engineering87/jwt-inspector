// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using JwtInspector.Core.Exceptions;
using JwtInspector.Core.Interfaces;
using Microsoft.IdentityModel.Tokens;
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
                var bytes = Base64UrlEncoder.DecodeBytes(input);
                return Encoding.UTF8.GetString(bytes);
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Invalid base64url content.", ex);
            }
        }

        /// <inheritdoc />
        public Dictionary<string, object> DecodePayload(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw new JwtInspectorException("Invalid token format. Expected a standard JWT with three base64-encoded sections.");

            try
            {
                var jwt = _tokenHandler.ReadJwtToken(token);
                var payload = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                foreach (var claim in jwt.Claims)
                    payload[claim.Type] = claim.Value;

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
                var parts = token.Split('.');
                if (parts.Length != 3)
                    throw new JwtInspectorException("Invalid JWT format. Expected three base64url segments.");

                var payloadJson = DecodeBase64Url(parts[1]); // RAW payload JSON
                var obj = JsonSerializer.Deserialize<T>(payloadJson, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                return obj ?? throw new JwtInspectorException("Payload does not match the target type.");
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
                var parts = token.Split('.');
                if (parts.Length != 3)
                    throw new JwtInspectorException("Invalid JWT format. Expected three base64url segments.");

                var payloadJson = DecodeBase64Url(parts[1]); // RAW payload JSON
                using var doc = JsonDocument.Parse(payloadJson);
                return JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
            }
            catch (JsonException ex)
            {
                throw new JwtInspectorException("Failed to parse the payload as JSON.", ex);
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
                var jwt = _tokenHandler.ReadJwtToken(token);
                var headers = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                foreach (var kv in jwt.Header)
                    headers[kv.Key] = kv.Value!;
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
                var jwt = _tokenHandler.ReadJwtToken(token);
                var map = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

                foreach (var g in jwt.Claims.GroupBy(c => c.Type, StringComparer.OrdinalIgnoreCase))
                    map[g.Key] = g.Skip(1).Any() ? g.Select(c => c.Value).ToArray() : g.First().Value;

                return map;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve claims from the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public object? GetCustomClaim(string token, string claimKey)
        {
            try
            {
                var claims = GetClaims(token); // case-insensitive dictionary
                return claims.TryGetValue(claimKey, out var value) ? value : null;
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
                var jwtToken = _tokenHandler.ReadJwtToken(token);
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
                return jwtToken.Id ?? string.Empty;
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
                return jwtToken.Header.Alg ?? string.Empty;
            }
            catch (Exception ex)
            {
                throw new JwtInspectorException("Failed to retrieve the signing algorithm from the JWT token.", ex);
            }
        }

        /// <inheritdoc />
        public string GetTokenSummary(string token)
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
                throw new JwtInspectorException("Invalid JWS format. Expected three base64url segments.");

            var headerJson = DecodeBase64Url(parts[0]);
            var payloadJson = DecodeBase64Url(parts[1]);
            var signature = parts[2];

            using var h = JsonDocument.Parse(headerJson);
            using var p = JsonDocument.Parse(payloadJson);

            var obj = new
            {
                Header = h.RootElement,
                Payload = p.RootElement,
                Signature = signature
            };
            return JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true });
        }

        /// <inheritdoc />
        public bool IsExpired(string token, TimeSpan? clockSkew = null)
        {
            var skew = clockSkew ?? TimeSpan.Zero;
            var jwt = _tokenHandler.ReadJwtToken(token);
            return jwt.ValidTo <= DateTime.UtcNow.Add(skew);
        }

        /// <inheritdoc />
        public bool IsValidFormat(string token)
        {
            try 
            { 
                _tokenHandler.ReadJwtToken(token); 
                return true; 
            }
            catch 
            { 
                return false; 
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


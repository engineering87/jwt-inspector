// (c) 2022 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using OpenJwtInspector.Exceptions;
using OpenJwtInspector.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace OpenJwtInspector.Services
{
    /// <summary>
    /// Service to decode JWT tokens.
    /// </summary>
    public class JwtDecoderService : IJwtDecoder
    {
        public string DecodeBase64Url(string input)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
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
            var payload = DecodePayload(token);

            return JsonSerializer.Serialize(payload, new JsonSerializerOptions
            {
                WriteIndented = true
            });
        }

        public (string Header, string Payload, string Signature) ExtractJwtParts(string token)
        {
            throw new NotImplementedException();
        }

        public string GetAudience(string token)
        {
            throw new NotImplementedException();
        }

        public IDictionary<string, object> GetClaims(string token)
        {
            throw new NotImplementedException();
        }

        public DateTime? GetExpirationDate(string token)
        {
            throw new NotImplementedException();
        }
    }
}


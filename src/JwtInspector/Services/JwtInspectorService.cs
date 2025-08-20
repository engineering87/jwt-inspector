// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using JwtInspector.Core.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace JwtInspector.Core.Services
{
    public class JwtInspectorService : IJwtInspector
    {
        private readonly IJwtDecoder _jwtDecoder;
        private readonly IJwtValidator _jwtValidator;

        public JwtInspectorService()
        {
            _jwtDecoder = new JwtDecoderService();
            _jwtValidator = new JwtValidatorService();
        }

        public JwtInspectorService(IJwtDecoder jwtDecoder, IJwtValidator jwtValidator)
        {
            _jwtDecoder = jwtDecoder;
            _jwtValidator = jwtValidator;
        }

        /// <inheritdoc />
        public string DecodeBase64Url(string input)
        {
            return _jwtDecoder.DecodeBase64Url(input);
        }

        /// <inheritdoc />
        public Dictionary<string, object> DecodePayload(string token)
        {
            return _jwtDecoder.DecodePayload(token);
        }

        /// <inheritdoc />
        public T DecodePayloadAs<T>(string token) where T : class
        {
            return _jwtDecoder.DecodePayloadAs<T>(token);
        }

        /// <inheritdoc />
        public string DecodePayloadAsJson(string token)
        {
            return _jwtDecoder.DecodePayloadAsJson(token);
        }

        /// <inheritdoc />
        public (string Header, string Payload, string Signature) ExtractJwtParts(string token)
        {
            return _jwtDecoder.ExtractJwtParts(token);
        }

        /// <inheritdoc />
        public IDictionary<string, object> GetAllHeaders(string token)
        {
            return _jwtDecoder.GetAllHeaders(token);
        }

        /// <inheritdoc />
        public string GetAudience(string token)
        {
            return _jwtDecoder.GetAudience(token);
        }

        /// <inheritdoc />
        public IDictionary<string, object> GetClaims(string token)
        {
            return _jwtDecoder.GetClaims(token);
        }

        /// <inheritdoc />
        public object? GetCustomClaim(string token, string claimKey)
        {
            return _jwtDecoder.GetCustomClaim(token, claimKey);
        }

        /// <inheritdoc />
        public DateTime? GetExpirationDate(string token)
        {
            return _jwtDecoder.GetExpirationDate(token);
        }

        /// <inheritdoc />
        public DateTime? GetIssuedAt(string token)
        {
            return _jwtDecoder.GetIssuedAt(token);
        }

        /// <inheritdoc />
        public string GetIssuer(string token)
        {
            return _jwtDecoder.GetIssuer(token);
        }

        /// <inheritdoc />
        public string GetJwtId(string token)
        {
            return _jwtDecoder.GetJwtId(token);
        }

        /// <inheritdoc />
        public string GetSigningAlgorithm(string token)
        {
            return _jwtDecoder.GetSigningAlgorithm(token);
        }

        /// <inheritdoc />
        public string GetTokenSummary(string token)
        {
            return _jwtDecoder.GetTokenSummary(token);
        }

        /// <inheritdoc />
        public bool HasClaim(string token, string claimKey)
        {
            return _jwtDecoder.HasClaim(token, claimKey);
        }

        /// <inheritdoc />
        public bool IsExpired(string token, TimeSpan? clockSkew = null)
        {
            return _jwtDecoder.IsExpired(token, clockSkew);
        }

        /// <inheritdoc />
        public bool IsValidFormat(string token)
        {
            return _jwtDecoder.IsValidFormat(token);
        }

        /// <inheritdoc />
        public bool ValidateAlgorithm(string token, string expectedAlgorithm)
        {
            return _jwtValidator.ValidateAlgorithm(token, expectedAlgorithm);
        }

        /// <inheritdoc />
        public bool ValidateClaims(string token, IDictionary<string, string> requiredClaims)
        {
            return _jwtValidator.ValidateClaims(token, requiredClaims);
        }

        /// <inheritdoc />
        public bool ValidateIssuerAndAudience(string token, string expectedIssuer, string expectedAudience)
        {
            return _jwtValidator.ValidateIssuerAndAudience(token, expectedIssuer, expectedAudience);
        }

        /// <inheritdoc />
        public bool ValidateIssuerSigningKey(string token, string signingKey)
        {
            return _jwtValidator.ValidateIssuerSigningKey(token, signingKey);
        }

        /// <inheritdoc />
        public bool ValidateLifetime(string token)
        {
            return _jwtValidator.ValidateLifetime(token);
        }

        /// <inheritdoc />
        public bool ValidateNotBefore(string token, TimeSpan? clockSkew = null)
        {
            return _jwtValidator.ValidateNotBefore(token, clockSkew);
        }

        /// <inheritdoc />
        public bool ValidateToken(string token, string secretKey)
        {
            return _jwtValidator.ValidateToken(token, secretKey);
        }

        /// <inheritdoc />
        public bool ValidateIssuerSigningKey(string token, SecurityKey key)
        {
            return _jwtValidator.ValidateIssuerSigningKey(token, key);
        }

        /// <inheritdoc />
        public bool VerifyIssuer(string token, string expectedIssuer)
        {
            return _jwtValidator.VerifyIssuer(token, expectedIssuer);
        }
    }
}

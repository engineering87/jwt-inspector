// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using JwtInspector.Core.Interfaces;

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

        public string DecodeBase64Url(string input)
        {
            return _jwtDecoder.DecodeBase64Url(input);
        }

        public Dictionary<string, object> DecodePayload(string token)
        {
            return _jwtDecoder.DecodePayload(token);
        }

        public string DecodePayloadAsJson(string token)
        {
            return _jwtDecoder.DecodePayloadAsJson(token);
        }

        public (string Header, string Payload, string Signature) ExtractJwtParts(string token)
        {
            return _jwtDecoder.ExtractJwtParts(token);
        }

        public string GetAudience(string token)
        {
            return _jwtDecoder.GetAudience(token);
        }

        public IDictionary<string, object> GetClaims(string token)
        {
            return _jwtDecoder.GetClaims(token);
        }

        public DateTime? GetExpirationDate(string token)
        {
            return _jwtDecoder.GetExpirationDate(token);
        }

        public DateTime? GetIssuedAt(string token)
        {
            return _jwtDecoder.GetIssuedAt(token);
        }

        public string GetJwtId(string token)
        {
            return _jwtDecoder.GetJwtId(token);
        }

        public string GetSigningAlgorithm(string token)
        {
            return _jwtDecoder.GetSigningAlgorithm(token);
        }

        public bool IsExpired(string token)
        {
            return _jwtDecoder.IsExpired(token);
        }

        public bool IsValidFormat(string token)
        {
            return _jwtDecoder.IsValidFormat(token);
        }

        public bool ValidateAlgorithm(string token, string expectedAlgorithm)
        {
            return _jwtValidator.ValidateAlgorithm(token, expectedAlgorithm);
        }

        public bool ValidateIssuerAndAudience(string token, string expectedIssuer, string expectedAudience)
        {
            return _jwtValidator.ValidateIssuerAndAudience(token, expectedIssuer, expectedAudience);
        }

        public bool ValidateLifetime(string token)
        {
            return _jwtValidator.ValidateLifetime(token);
        }

        public bool ValidateToken(string token, string secretKey)
        {
            return _jwtValidator.ValidateToken(token, secretKey);
        }

        public bool VerifyIssuer(string token, string expectedIssuer)
        {
            return _jwtValidator.VerifyIssuer(token, expectedIssuer);
        }
    }
}

// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
namespace JwtInspector.Core.Interfaces
{
    /// <summary>
    /// Provides functionality to decode JWT tokens.
    /// </summary>
    public interface IJwtDecoder
    {
        /// <summary>
        /// Decodes the payload of a JWT token without validating the signature.
        /// </summary>
        /// <param name="token">The JWT token to decode.</param>
        /// <returns>A dictionary containing the payload claims.</returns>
        Dictionary<string, object> DecodePayload(string token);


        /// <summary>
        /// Decodes the payload of a JWT token and returns it in JSON format.
        /// </summary>
        /// <param name="token">The JWT token to decode.</param>
        /// <returns>A JSON string with the payload claims.</returns>
        string DecodePayloadAsJson(string token);

        /// <summary>
        /// Retrieves the claims from the JWT token.
        /// </summary>
        /// <param name="token">The JWT token to decode.</param>
        /// <returns>A dictionary of claims where the key is the claim type and the value is the claim value.</returns>
        IDictionary<string, object> GetClaims(string token);

        /// <summary>
        /// Retrieves the audience claim from the JWT token.
        /// </summary>
        /// <param name="token">The JWT token to decode.</param>
        /// <returns>The audience claim value, or an empty string if not available.</returns>
        string GetAudience(string token);

        /// <summary>
        /// Retrieves the expiration date from the JWT token.
        /// </summary>
        /// <param name="token">The JWT token to decode.</param>
        /// <returns>The expiration date of the token, or null if not available.</returns>
        DateTime? GetExpirationDate(string token);

        /// <summary>
        /// Decodes a Base64 URL-encoded string to its original representation.
        /// </summary>
        /// <param name="input">The Base64 URL-encoded string.</param>
        /// <returns>The decoded string.</returns>
        string DecodeBase64Url(string input);

        /// <summary>
        /// Extracts the header, payload, and signature from the JWT token.
        /// </summary>
        /// <param name="token">The JWT token to extract the parts from.</param>
        /// <returns>A tuple containing the header, payload, and signature of the token.</returns>
        (string Header, string Payload, string Signature) ExtractJwtParts(string token);

        /// <summary>
        /// Retrieves the issued-at timestamp from the JWT token.
        /// </summary>
        /// <param name="token">The JWT token to decode.</param>
        /// <returns>The issued-at timestamp of the token, or null if not available.</returns>
        DateTime? GetIssuedAt(string token);

        /// <summary>
        /// Checks if the JWT token is expired.
        /// </summary>
        /// <param name="token">The JWT token to check.</param>
        /// <param name="clockSkew">The TimeSpan skew.</param>
        /// <returns>True if the token is expired, false otherwise.</returns>
        bool IsExpired(string token, TimeSpan? clockSkew = null);

        /// <summary>
        /// Retrieves the JWT ID (jti) claim from the JWT token.
        /// </summary>
        /// <param name="token">The JWT token to decode.</param>
        /// <returns>The JWT ID if present, or an empty string otherwise.</returns>
        string GetJwtId(string token);

        /// <summary>
        /// Retrieves the signing algorithm used in the JWT token.
        /// </summary>
        /// <param name="token">The JWT token to decode.</param>
        /// <returns>The algorithm used for signing the token.</returns>
        string GetSigningAlgorithm(string token);

        /// <summary>
        /// Checks if the token has a valid JWT format.
        /// </summary>
        /// <param name="token">The JWT token to validate.</param>
        /// <returns>True if the token has a valid JWT format, false otherwise.</returns>
        bool IsValidFormat(string token);

        /// <summary>
        /// Retrieves the issuer claim from the JWT token.
        /// </summary>
        /// <param name="token">The JWT token to decode.</param>
        /// <returns>The issuer claim value, or an empty string if not available.</returns>
        string GetIssuer(string token);

        /// <summary>
        /// Retrieves a specific custom claim from the JWT token.
        /// </summary>
        /// <param name="token">The JWT token to decode.</param>
        /// <param name="claimKey">The key of the claim to retrieve.</param>
        /// <returns>The value of the custom claim, or null if not available.</returns>
        object? GetCustomClaim(string token, string claimKey);

        /// <summary>
        /// Retrieves all headers from the JWT token.
        /// </summary>
        /// <param name="token">The JWT token to decode.</param>
        /// <returns>A dictionary containing all headers in the token.</returns>
        IDictionary<string, object> GetAllHeaders(string token);

        /// <summary>
        /// Deserializes the JWT payload into a strongly-typed object.
        /// </summary>
        /// <typeparam name="T">The type of the object to deserialize into.</typeparam>
        /// <param name="token">The JWT token to decode.</param>
        /// <returns>An instance of the specified type populated with the payload data.</returns>
        T DecodePayloadAs<T>(string token) where T : class;

        /// <summary>
        /// Generates a human-readable summary of the JWT token contents.
        /// </summary>
        /// <param name="token">The JWT token to analyze.</param>
        /// <returns>A formatted string summarizing the header, payload, and other details of the token.</returns>
        string GetTokenSummary(string token);

        /// <summary>
        /// Checks if the JWT token contains a specific claim.
        /// </summary>
        /// <param name="token">The JWT token to inspect.</param>
        /// <param name="claimKey">The key of the claim to check.</param>
        /// <returns>True if the claim exists, false otherwise.</returns>
        bool HasClaim(string token, string claimKey);
    }
}

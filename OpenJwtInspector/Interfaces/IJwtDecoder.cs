// (c) 2022 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
namespace OpenJwtInspector.Interfaces
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
        /// <returns>The audience claim value.</returns>
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
    }
}

// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using Microsoft.IdentityModel.Tokens;

namespace JwtInspector.Core.Interfaces
{
    /// <summary>
    /// Provides functionality to validate JWT tokens.
    /// </summary>
    public interface IJwtValidator
    {
        /// <summary>
        /// Validates a JWT token with a given secret key.
        /// </summary>
        /// <param name="token">The JWT token to validate.</param>
        /// <param name="secretKey">The secret key for token signature validation.</param>
        /// <returns>True if the token is valid, otherwise false.</returns>
        bool ValidateToken(string token, string secretKey);

        /// <summary>
        /// Validates that the token signature matches the provided asymmetric or symmetric <see cref="SecurityKey"/>.  
        /// This check ignores issuer, audience and lifetime validation, focusing only on the signing key.
        /// Returns <c>true</c> if the token is valid with the given key; otherwise <c>false</c>.
        /// </summary>
        bool ValidateIssuerSigningKey(string token, SecurityKey key);

        /// <summary>
        /// Verifies that the issuer of the token matches the expected issuer.
        /// </summary>
        /// <param name="token">The JWT token to validate.</param>
        /// <param name="expectedIssuer">The expected issuer claim value.</param>
        /// <returns>True if the token issuer matches the expected issuer, false otherwise.</returns>
        bool VerifyIssuer(string token, string expectedIssuer);

        /// <summary>
        /// Verifies that the issuer and audience of the token match the expected values.
        /// </summary>
        /// <param name="token">The JWT token to validate.</param>
        /// <param name="expectedIssuer">The expected issuer claim value.</param>
        /// <param name="expectedAudience">The expected audience claim value.</param>
        /// <returns>True if both the issuer and audience match the expected values, false otherwise.</returns>
        bool ValidateIssuerAndAudience(string token, string expectedIssuer, string expectedAudience);

        /// <summary>
        /// Validates the token's lifetime based on the expiration date.
        /// </summary>
        /// <param name="token">The JWT token to validate.</param>
        /// <returns>True if the token is still valid (not expired), false otherwise.</returns>
        bool ValidateLifetime(string token);

        /// <summary>
        /// Verifies that the algorithm used to sign the token matches the expected algorithm.
        /// </summary>
        /// <param name="token">The JWT token to validate.</param>
        /// <param name="expectedAlgorithm">The expected signing algorithm.</param>
        /// <returns>True if the token uses the expected algorithm, false otherwise.</returns>
        bool ValidateAlgorithm(string token, string expectedAlgorithm);

        /// <summary>
        /// Ensures that the token was signed using the correct signing key.
        /// </summary>
        /// <param name="token">The JWT token to validate.</param>
        /// <param name="signingKey">The expected signing key.</param>
        /// <returns>True if the signing key is valid, otherwise false.</returns>
        bool ValidateIssuerSigningKey(string token, string signingKey);

        /// <summary>
        /// Validates specific claims in the token (e.g., roles, permissions).
        /// </summary>
        /// <param name="token">The JWT token to validate.</param>
        /// <param name="requiredClaims">Key-value pairs representing required claims.</param>
        /// <returns>True if all required claims are present and valid, false otherwise.</returns>
        bool ValidateClaims(string token, IDictionary<string, string> requiredClaims);

        /// <summary>
        /// Validates that the token is not used before the specified 'Not Before' time (nbf claim).
        /// </summary>
        /// <param name="token">The JWT token to validate.</param>
        /// <param name="clockSkew">
        /// Optional clock skew to account for differences between system clocks.  
        /// If provided, the 'nbf' validation allows for the specified offset.
        /// </param>
        /// <returns>True if the token is valid according to the 'nbf' claim, false otherwise.</returns>
        bool ValidateNotBefore(string token, TimeSpan? clockSkew = null);
    }
}

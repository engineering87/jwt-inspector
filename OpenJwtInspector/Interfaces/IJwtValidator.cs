// (c) 2022 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)

namespace OpenJwtInspector.Interfaces
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
        DateTime? GetExpirationDate(string token);
    }
}

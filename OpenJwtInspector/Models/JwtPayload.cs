// (c) 2022 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
namespace OpenJwtInspector.Models
{
    /// <summary>
    /// Represents the payload of a JWT token.
    /// </summary>
    public class JwtPayload
    {
        public Dictionary<string, object>? Claims { get; set; }
    }
}

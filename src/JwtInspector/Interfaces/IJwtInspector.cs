// (c) 2022 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
namespace JwtInspector.Core.Interfaces
{
    /// <summary>
    /// Provides functionality to decode, validate, and inspect JWT tokens.
    /// </summary>
    public interface IJwtInspector : IJwtDecoder, IJwtValidator
    {

    }
}
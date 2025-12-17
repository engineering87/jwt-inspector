// (c) 2024-2025 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using JwtInspector.Core.Interfaces;
using JwtInspector.Core.Services;
using Microsoft.Extensions.DependencyInjection;

namespace JwtInspector.Core.DependencyInjection
{
    /// <summary>
    /// Dependency injection extensions for registering JwtInspector services.
    /// </summary>
    public static class JwtInspectorServiceCollectionExtensions
    {
        /// <summary>
        /// Registers all JwtInspector core services into the dependency injection container.
        /// </summary>
        /// <param name="services">The service collection to add the JwtInspector services to.</param>
        /// <returns>The same <see cref="IServiceCollection"/> instance for chaining.</returns>
        public static IServiceCollection AddJwtInspector(this IServiceCollection services)
        {
            services.AddSingleton<IJwtDecoder, JwtDecoderService>();
            services.AddSingleton<IJwtValidator, JwtValidatorService>();
            services.AddSingleton<IJwtInspector, JwtInspectorService>();

            return services;
        }
    }
}

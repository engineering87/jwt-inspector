// (c) 2024-2026 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using JwtInspector.Core.DependencyInjection;
using JwtInspector.Core.Interfaces;
using Microsoft.Extensions.DependencyInjection;

namespace JwtInspector.Tests;

public sealed class JwtInspectorFixture : IDisposable
{
    public ServiceProvider Provider { get; }
    public IJwtInspector Inspector { get; }

    public JwtInspectorFixture()
    {
        var services = new ServiceCollection();
        services.AddJwtInspector();

        Provider = services.BuildServiceProvider(validateScopes: true);
        Inspector = Provider.GetRequiredService<IJwtInspector>();
    }

    public void Dispose() => Provider.Dispose();
}

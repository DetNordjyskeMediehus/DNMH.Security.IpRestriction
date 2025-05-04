using Microsoft.AspNetCore.Builder;

namespace DNMH.Security.IpRestriction;

/// <summary>
/// Extension methods for <see cref="IApplicationBuilder"/>.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds required middleware for IP Restriction.
    /// </summary>
    public static IApplicationBuilder UseIpRestriction(this IApplicationBuilder app)
    {
        app.UseMiddleware<IpRestrictionMiddleware>();
        return app;
    }
}

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace DNMH.Security.IpRestriction;

/// <summary>
/// Extension methods for the <see cref="IServiceCollection"/>
/// </summary>
public static partial class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds necessary IP Restriction services.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="configureOptions">The action used to configure options.</param>
    public static IServiceCollection AddIpRestriction(this IServiceCollection services, Action<IpRestrictionOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services
            .AddOptions<IpRestrictionOptions>()
            .Configure(configureOptions)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        RegisterServices(services);

        return services;
    }

    /// <summary>
    /// Adds necessary IP Restriction services.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="configureOptions">The action used to configure options.</param>
    public static IServiceCollection AddIpRestriction(this IServiceCollection services, Action<IpRestrictionOptions, IServiceProvider> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services
            .AddOptions<IpRestrictionOptions>()
            .Configure(configureOptions)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        RegisterServices(services);

        return services;
    }

    private static void RegisterServices(IServiceCollection services)
    {
        services.AddSingleton<IValidateOptions<IpRestrictionOptions>, IpRestrictionValidateOptions>();
        services.AddSingleton<IIpRestrictionAuditor, IpRestrictionAuditor>();
    }
}

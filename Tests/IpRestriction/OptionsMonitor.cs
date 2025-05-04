using Microsoft.Extensions.Options;

namespace DNMH.Security.IpRestriction.Tests;

internal class OptionsMonitor<T>(T currentValue) : IOptionsMonitor<T>
{
    public T CurrentValue => currentValue;

    public T Get(string? name) => currentValue;

    public IDisposable? OnChange(Action<T, string?> listener)
    {
        throw new NotImplementedException();
    }
}

internal static class OptionsMonitor
{
    public static IOptionsMonitor<T> Create<T>(T currentValue) => new OptionsMonitor<T>(currentValue);
}

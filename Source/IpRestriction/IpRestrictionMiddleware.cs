using Microsoft.AspNetCore.Http;

namespace DNMH.Security.IpRestriction;

internal sealed class IpRestrictionMiddleware(RequestDelegate next, IIpRestrictionAuditor auditor)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var endpoint = context.GetEndpoint();
        var attribute = endpoint?.Metadata.GetMetadata<IpRestrictedAttribute>();
        var remoteIpAddress = context.Connection.RemoteIpAddress;
        if (!auditor.IsIpAllowed(attribute?.Key, remoteIpAddress))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        await next(context);
    }
}

using Microsoft.AspNetCore.Mvc;

namespace DNMH.Security.IpRestriction.OpenAPI.Sample.Controllers;

[ApiController]
[Route("[controller]")]
public class TestIpController : ControllerBase
{
    /// <summary>
    /// Tests no ip restriction.
    /// </summary>
    [HttpGet]
    public string Get() => "Congratulations! You have access - as you should!";

    /// <summary>
    /// Tests localhost ip restriction.
    /// </summary>
    [HttpGet("nolocal")]
    [IpRestricted("NoLocalhost")] // "NoLocalhost" is configured in appsettings.json
    public string GetNoLocal() => "Woops! You should not have access, if you are visiting from localhost.";
}

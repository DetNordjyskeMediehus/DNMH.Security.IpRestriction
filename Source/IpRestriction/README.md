# DNMH.Security.IpRestriction

## Overview

`DNMH.Security.IpRestriction` is a .NET library that provides IP restriction middleware for your web applications. It allows you to restrict access to your application based on a configurable list of allowed or denied IP addresses.

## Installation

You can install this library using NuGet. Simply run the following command:

```bash
dotnet add package DNMH.Security.IpRestriction
```

This will add IP restriction functionality to your .NET application.

## Usage

To use this library, follow these steps:

1. In your `Startup.cs` file (or `Program.cs` for minimal APIs), configure the IP restriction middleware:

```csharp
builder.Services.AddIpRestriction(options => 
{ 
    options.Global.Deny.Add("192.168.1.1"); 
    options.DeniedIPs.Add("10.0.0.1"); 
});
```


2. Optionally, you can use the `[IpRestricted("profileKey")]` attribute to apply IP restrictions to specific controllers or actions:

```csharp
[Route("api/[controller]")] 
[ApiController] 
public class MyController : ControllerBase 
{ 
    [HttpGet] 
    [IpRestricted("myProfile")] 
    public IActionResult Get() 
    { 
        return Ok("Access granted!"); 
    } 
}
```

## License

This library is licensed under the [MIT License](LICENSE).
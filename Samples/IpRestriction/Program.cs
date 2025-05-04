using DNMH.Security.IpRestriction;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Adds IP restriction based on the given configuration.
builder.Services.AddIpRestriction(options => builder.Configuration.GetRequiredSection("IpRestrictions").Bind(options));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

// Registers required middleware for IP Restriction.
app.UseIpRestriction();

app.Run();

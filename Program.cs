// The 'using' directives import namespaces, making their types available without full qualification.
using DotNetEnv;
using Lensisku;
using Lensisku.Data;
using Microsoft.EntityFrameworkCore;
using OpenTelemetry.Logs;
using OpenTelemetry.Resources;

// ASP.NET Core namespaces for authentication, authorization, and MVC.
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Lensisku.Auth.Services;
// For policy constants
using Lensisku.Auth.Controllers;

// Loads environment variables from a .env file at the application's root.
// This is useful for managing configuration settings, especially secrets, outside of source control.
Env.Load(); // Load .env file

// WebApplication.CreateBuilder initializes a new instance of the WebApplicationBuilder with preconfigured defaults.
// This builder is used to configure services and the application's request processing pipeline.
var builder = WebApplication.CreateBuilder(args);

// Configure OpenTelemetry logging
builder.Logging.ClearProviders();
builder.Logging.AddOpenTelemetry(options =>
{
    options.SetResourceBuilder(ResourceBuilder.CreateDefault()
        .AddService(builder.Environment.ApplicationName));
    
    options.AddConsoleExporter(opt =>
    {
        opt.Targets = OpenTelemetry.Exporter.ConsoleExporterOutputTargets.Console;
    });
    
    // Include scopes in logs
    options.IncludeScopes = true;
    // Parse state values
    options.ParseStateValues = true;
    // Include formatted message
    options.IncludeFormattedMessage = true;
});

// Configuration for JWT
// Creates an instance of JwtSettings to hold JWT configuration.
var jwtSettings = new JwtSettings();
// Binds configuration values from the "JwtSettings" section of appsettings.json (or other config sources)
// to the jwtSettings object. This is part of ASP.NET Core's configuration system.
builder.Configuration.GetSection("JwtSettings").Bind(jwtSettings); // For appsettings.json

// Fallback to environment variables if not in appsettings.json
jwtSettings.Secret ??= Environment.GetEnvironmentVariable("JWT_SECRET");
jwtSettings.Issuer ??= Environment.GetEnvironmentVariable("JWT_ISSUER");
jwtSettings.Audience ??= Environment.GetEnvironmentVariable("JWT_AUDIENCE");
// REFRESH_TOKEN_SECRET will be handled by TokenService directly from Env if needed for generation
// Provides a fallback mechanism to load JWT settings from environment variables if they are not found in appsettings.json.

if (string.IsNullOrEmpty(jwtSettings.Secret))
{
    throw new InvalidOperationException("JWT_SECRET not found in configuration.");
}
// Registers JwtSettings as a singleton service in the dependency injection (DI) container.
// This makes the JwtSettings object available to other parts of the application via DI.
builder.Services.AddSingleton(jwtSettings); // Make settings available via DI

// Configure DbContext
// Retrieves the database connection string from environment variables or appsettings.json.
var connectionString = Environment.GetEnvironmentVariable("DATABASE_URL");
if (string.IsNullOrEmpty(connectionString))
{
    // Fallback for local development if DATABASE_URL is not in .env but in appsettings or user secrets
    connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
}

if (string.IsNullOrEmpty(connectionString))
{
    throw new InvalidOperationException("Database connection string 'DATABASE_URL' or 'DefaultConnection' not found.");
}

// Registers AppDbContext with the DI container, configuring it to use PostgreSQL.
// 'options.UseNpgsql(connectionString)' specifies the database provider and connection string.
// The service lifetime is Scoped by default for DbContext, meaning one instance per HTTP request.
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(connectionString));


// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
// Adds services required for controllers (API endpoints).
builder.Services.AddControllers();
// Adds API Explorer services, necessary for Swagger/OpenAPI documentation generation.
builder.Services.AddEndpointsApiExplorer(); // Required for Swagger
// Adds Swagger generation services to the DI container. Swagger provides a UI for exploring and testing APIs.
builder.Services.AddSwaggerGen(); // Adds Swagger generation services

// Register custom services
// Scoped services are created once per client request (connection).
// These lines register various custom services (interfaces and their implementations) with the DI container.
builder.Services.AddScoped<IPasswordHasherService, PasswordHasherService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IUserSessionService, UserSessionService>();
// AuthService depends on other services, which will be resolved by the DI container when AuthService is created.
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IUserService, UserService>();

// Add Authentication and Authorization
// Configures authentication services.
// DefaultAuthenticateScheme and DefaultChallengeScheme are set to JwtBearerDefaults.AuthenticationScheme,
// meaning JWT Bearer authentication will be used by default.
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // Configures JWT Bearer authentication options.
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret!)),
        ValidateIssuer = !string.IsNullOrEmpty(jwtSettings.Issuer), // Validate if set
        ValidIssuer = jwtSettings.Issuer,
        ValidateAudience = !string.IsNullOrEmpty(jwtSettings.Audience), // Validate if set
        ValidAudience = jwtSettings.Audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero // Or a small tolerance
    };
});

// Configures authorization services.
builder.Services.AddAuthorization(options =>
{

    // Policies provide a flexible and reusable way to define authorization rules.
              
    // Example: Admin role policy (alternative to permission-based, or can be combined)
    // options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    // Note: RequireRole checks against ClaimTypes.Role. Our "role" claim in JWT is custom.
    // To use RequireRole effectively, ensure TokenService adds role to claims with ClaimTypes.Role
    // or create a policy that checks the custom "role" claim:
    options.AddPolicy("AdminRoleRequired", policy =>
        policy.RequireAuthenticatedUser()
              .RequireClaim("role", "Admin"));
});


// Builds the WebApplication instance from the configured services.
var app = builder.Build();

// Global exception handling middleware
app.UseExceptionHandler(exceptionHandlerApp =>
{
    exceptionHandlerApp.Run(async context =>
    {
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
        var exceptionHandler = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>();
        
        if (exceptionHandler?.Error != null)
        {
            logger.LogError(exceptionHandler.Error,
                "Unhandled exception: {Message}", exceptionHandler.Error.Message);
        }

        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await context.Response.WriteAsync("An unexpected error occurred");
    });
});

// Configure the HTTP request pipeline.
// The order of middleware components in the pipeline is crucial.

// Redirects HTTP requests to HTTPS. Important for security.
app.UseHttpsRedirection(); // Should be early

// Adds authentication middleware to the pipeline. This middleware identifies users based on incoming tokens.
app.UseAuthentication(); // IMPORTANT: Before UseAuthorization
// Adds authorization middleware to the pipeline. This middleware enforces access control rules (policies, roles).
app.UseAuthorization();


/*
// Apply migrations - good practice for development, can be conditional
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    // Check if there are any pending migrations and apply them
    // For production, a separate migration strategy is often used.
    if (dbContext.Database.GetPendingMigrations().Any())
    {
        dbContext.Database.Migrate();
    }
}
*/

// Conditional middleware configuration based on the environment.
if (app.Environment.IsDevelopment())
{
    // Enables Swagger middleware to serve the generated OpenAPI specification as a JSON endpoint.
    app.UseSwagger(); // Enable middleware to serve generated Swagger as a JSON endpoint.
    // Enables Swagger UI middleware, providing an interactive HTML interface for the API.
    app.UseSwaggerUI(); // Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.), specifying the Swagger JSON endpoint.
}

// app.UseHttpsRedirection(); // Removed duplicate, already called on line 85

// Maps controller actions to routes. This enables routing for API endpoints defined in controllers.
app.MapControllers();


// This is an example of a minimal API endpoint defined directly in Program.cs.
var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
// This is an example of a minimal API endpoint defined directly in Program.cs.
{
    var forecast =  Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast");

// Runs the application, starting the web server and listening for incoming requests.
app.Run();

// Record types are concise ways to define immutable data-carrying types.
record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

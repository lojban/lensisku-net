// Helper class for JWT Settings
// Placed at the root of archive/lensisku-net for simplicity during this task.
// Consider moving to a 'Configuration' or 'Models/Configuration' folder in a real project.

// This namespace declaration groups related classes. 'Lensisku' is the root namespace for the project.
namespace Lensisku // Assuming the root namespace from the .csproj
{
    // This class is a Plain Old CLR Object (POCO) used to hold JWT (JSON Web Token) configuration settings.
    // These settings are typically loaded from configuration files (e.g., appsettings.json, .env) or environment variables.
    public class JwtSettings
    {
        public string? Secret { get; set; }
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
        public int AccessTokenExpirationMinutes { get; set; } = 60; // Example: 1 hour
        public int RefreshTokenExpirationDays { get; set; } = 7;  // Example: 7 days
    }
}
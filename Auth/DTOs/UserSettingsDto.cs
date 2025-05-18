using System;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used to transfer user settings data.
    // It typically represents the current state of a user's application-specific settings.
    public class UserSettingsDto
    {
        public int UserId { get; set; }
        // Example setting: optimal retention for some learning algorithm.
        public double OptimalRetention { get; set; }
        // Timestamp of when these settings were last calculated or updated.
        public DateTime LastCalculated { get; set; }
    }
}

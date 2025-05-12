using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to update user settings.
    public class UpdateUserSettingsRequestDto
    {
        [Required]
        [Range(0.0, 1.0)] // Assuming optimal retention is a value between 0 and 1
        // The new value for the optimal retention setting.
        // [Range] attribute validates that the value falls within the specified range.
        public double OptimalRetention { get; set; }
    }
}

using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to update a user's profile information.
    // All properties are optional, allowing partial updates.
    public class UpdateProfileRequestDto
    {
        [StringLength(100, MinimumLength = 3)]
        // Optional new username. Validation ensures it meets length requirements if provided.
        public string? Username { get; set; }

        [StringLength(255)]
        // Optional new real name.
        public string? RealName { get; set; }

        [StringLength(512)]
        [Url]
        // Optional new URL (e.g., personal website). [Url] attribute validates the format.
        public string? Url { get; set; }

        // Optional personal information/bio.
        public string? Personal { get; set; } // No specific length, could be large text
    }
}

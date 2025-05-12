using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for the first step of an authenticated password change process.
    // It requires the user's current password for verification.
    public class InitiatePasswordChangeRequestDto
    {
        [Required]
        // The user's current password.
        public string CurrentPassword { get; set; } = string.Empty;
    }
}

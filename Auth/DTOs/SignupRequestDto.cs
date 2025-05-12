using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for user signup (registration) requests.
    // It contains the necessary information for creating a new user account.
    public class SignupRequestDto
    {
        [Required]
        [StringLength(100, MinimumLength = 3)]
        // The desired username for the new account.
        public string Username { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        [StringLength(255)]
        // The email address for the new account.
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(100, MinimumLength = 8)] // Example password policy
        // The chosen password for the new account. Password policies (length, complexity) are enforced here via attributes.
        public string Password { get; set; } = string.Empty;
    }
}

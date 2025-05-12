using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for user login requests.
    public class LoginRequestDto
    {
        [Required]
        [StringLength(255)] // Accommodates email or username
        // The username or email address provided by the user for login.
        public string UsernameOrEmail { get; set; } = string.Empty;

        [Required]
        // The password provided by the user.
        public string Password { get; set; } = string.Empty;
    }
}

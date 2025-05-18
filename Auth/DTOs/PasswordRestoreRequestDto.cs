using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to restore/reset a password using a token and session ID
    // (typically obtained from a password reset link sent via email).
    public class PasswordRestoreRequestDto
    {
        [Required]
        // The password reset token from the email link.
        public string Token { get; set; } = string.Empty;

        [Required]
        // The session ID associated with the password reset request, also from the email link.
        public string SessionId { get; set; } = string.Empty;

        [Required]
        [StringLength(100, MinimumLength = 8)] // Example password policy
        // The new password chosen by the user.
        public string NewPassword { get; set; } = string.Empty;
    }
}

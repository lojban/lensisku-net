using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to initiate a password reset process (typically for forgotten passwords).
    public class PasswordResetRequestDto
    {
        [Required]
        [EmailAddress]
        [StringLength(255)]
        // The email address of the user requesting the password reset.
        public string Email { get; set; } = string.Empty;
    }
}

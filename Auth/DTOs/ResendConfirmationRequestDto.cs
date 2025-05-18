using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to resend an email confirmation link.
    public class ResendConfirmationRequestDto
    {
        [Required]
        [EmailAddress]
        [StringLength(255)]
        // The email address to which the confirmation link should be resent.
        // [EmailAddress] attribute validates that the string is a valid email format.
        public string Email { get; set; } = string.Empty;
    }
}

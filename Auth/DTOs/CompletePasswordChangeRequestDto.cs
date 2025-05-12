using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for the second step of an authenticated password change process.
    // It requires a verification ID and code (obtained from the initiation step) and the new password.
    public class CompletePasswordChangeRequestDto
    {
        [Required]
        // The verification ID received from the password change initiation step.
        public string VerificationId { get; set; } = string.Empty;

        [Required]
        [StringLength(10, MinimumLength = 6)]
        // The verification code (e.g., sent via email) to confirm the password change.
        public string VerificationCode { get; set; } = string.Empty;

        [Required]
        [StringLength(100, MinimumLength = 8)] // Example password policy
        // The new password chosen by the user.
        public string NewPassword { get; set; } = string.Empty;
    }
}

namespace Lensisku.Auth.DTOs
{
    // This DTO represents the response from the first step of an authenticated password change process.
    // It typically includes a message and a verification ID to be used in the next step.
    public class InitiatePasswordChangeResponseDto
    {
        public string Message { get; set; } = string.Empty;
        // A unique identifier for this password change attempt, used to link the initiation and completion steps.
        public string VerificationId { get; set; } = string.Empty;
    }
}

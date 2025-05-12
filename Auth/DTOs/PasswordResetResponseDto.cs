namespace Lensisku.Auth.DTOs
{
    // This DTO represents the response from a "request password reset" operation.
    // It includes a success flag, a message, and optionally a session ID for the reset process.
    public class PasswordResetResponseDto
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        // The session ID can be used to link the reset request to the actual password restoration step.
        public string? SessionId { get; set; }
    }
}

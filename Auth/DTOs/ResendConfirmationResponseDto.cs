namespace Lensisku.Auth.DTOs
{
    // This DTO represents the response from an operation to resend an email confirmation link.
    // It includes a success flag and a message.
    public class ResendConfirmationResponseDto
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}
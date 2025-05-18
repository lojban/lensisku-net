namespace Lensisku.Auth.DTOs
{
    // This DTO represents the response from the final step of an authenticated password change.
    // It indicates success and provides a confirmation message.
    public class CompletePasswordChangeResponseDto
    {
        public string Message { get; set; } = string.Empty;
        public bool Success { get; set; }
    }
}
namespace Lensisku.Auth.DTOs
{
    // This DTO represents the response from a "block user" or "unblock user" operation.
    // It indicates success and provides a message.
    public class BlockUserResponseDto
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}
namespace Lensisku.Auth.DTOs
{
    // This DTO represents the response from a follow or unfollow operation.
    // It includes a success flag and a message indicating the outcome.
    public class FollowResponseDto
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}
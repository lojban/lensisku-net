namespace Lensisku.Auth.DTOs
{
    // This DTO represents the response from an "assign role" operation.
    // It typically includes a success flag and a message indicating the outcome.
    public class AssignRoleResponseDto
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}
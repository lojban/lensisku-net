namespace Lensisku.Auth.DTOs
{
    // This DTO is used to transfer user profile information, typically in response to a profile request.
    // It includes publicly viewable or editable profile fields.
    public class ProfileResponseDto
    {
        public string? RealName { get; set; }
        public string? Url { get; set; }
        public string? Personal { get; set; }
    }
}
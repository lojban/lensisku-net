using System;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used to transfer user profile image data.
    // It's typically used when retrieving a profile image.
    public class UserProfileImageDto
    {
        public int UserId { get; set; }
        // The image data as a byte array.
        public byte[] ImageData { get; set; } = Array.Empty<byte>();
        // The MIME type of the image (e.g., "image/jpeg", "image/png").
        public string MimeType { get; set; } = string.Empty;
        public DateTime UpdatedAt { get; set; }
    }
}
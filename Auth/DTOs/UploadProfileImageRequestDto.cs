using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to upload a user's profile image.
    public class UploadProfileImageRequestDto
    {
        [Required]
        // IFormFile represents a file sent with an HTTP request (typically multipart/form-data).
        // This property will hold the uploaded image file.
        public IFormFile ImageFile { get; set; } = null!;
    }
}

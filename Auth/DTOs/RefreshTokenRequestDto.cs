using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to refresh an access token using a refresh token.
    public class RefreshTokenRequestDto
    {
        [Required]
        // The refresh token provided by the client.
        public string RefreshToken { get; set; } = string.Empty;
    }
}

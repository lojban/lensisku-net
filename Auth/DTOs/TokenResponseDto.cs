namespace Lensisku.Auth.DTOs
{
    // This DTO represents the response containing authentication tokens (access and refresh).
    // It's typically returned after a successful login or token refresh operation.
    public class TokenResponseDto
    {
        // The access token, used to authenticate requests to protected API endpoints.
        public string AccessToken { get; set; } = string.Empty;
        // The refresh token, used to obtain a new access token when the current one expires.
        public string RefreshToken { get; set; } = string.Empty;
    }
}

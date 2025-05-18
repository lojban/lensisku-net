namespace Lensisku.Auth.DTOs
{
    public class AuthResponse
    {
        public string? AccessToken { get; set; }
        public string? Message { get; set; }
        // According to the spec, only AccessToken is needed for signup response initially.
        // RefreshToken and ExpiresIn are part of TokenResponse for login.
    }
}
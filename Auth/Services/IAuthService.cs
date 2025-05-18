using Lensisku.Auth.DTOs;
using System.Threading.Tasks;

namespace Lensisku.Auth.Services
{
    // IAuthService defines the contract for all authentication-related operations.
    // This interface allows for decoupling the controllers (or other consumers) from the concrete implementation of authentication logic,
    // facilitating dependency injection and testability.
    // Defines the contract for authentication operations
    public interface IAuthService
    {
        // Handles user registration. Takes signup details, returns success status, tokens (if applicable), and a message.
        Task<AuthResponse> SignupAsync(SignupRequest request);
        
        // Handles user login. Takes login credentials and client info (IP, UserAgent), returns tokens and status.
        Task<TokenResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent);
        
        // Confirms a user's email address using a provided token.
        Task ConfirmEmailAsync(string token);
        
        // Resends an email confirmation link to a user.
        Task ResendConfirmationEmailAsync(ResendConfirmationRequestDto request);
        
        // Initiates a password reset process (e.g., for forgotten passwords).
        Task<PasswordResetResponseDto> RequestPasswordResetAsync(PasswordResetRequestDto request);
        
        // Completes a password reset using a token and new password.
        Task RestorePasswordAsync(PasswordRestoreRequestDto request);
        
        // Refreshes authentication tokens using a valid refresh token.
        Task<TokenResponse> RefreshTokenAsync(RefreshTokenRequest request, string ipAddress, string userAgent);
        // Initiates a password change for an authenticated user (requires current password).
        Task<InitiatePasswordChangeResponseDto> InitiatePasswordChangeAsync(int userId, InitiatePasswordChangeRequestDto request);
        
        // Completes an authenticated password change using a verification code and new password.
        Task CompletePasswordChangeAsync(int userId, CompletePasswordChangeRequestDto request);

        // Handles user logout, potentially invalidating a specific session.
        Task LogoutAsync(int userId, System.Guid? sessionId);
    }
}

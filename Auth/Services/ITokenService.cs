using Lensisku.Auth.Models;
using System.Collections.Generic;
using System.Security.Claims;

namespace Lensisku.Auth.Services
{
    // ITokenService defines the contract for operations related to generating and validating security tokens (e.g., JWTs).
    public interface ITokenService
    {
        // Generates an access token for a given user, including their permissions and an optional session ID.
        // Access tokens are typically short-lived and grant access to protected resources.
        string GenerateAccessToken(User user, IEnumerable<string> permissions, Guid? sessionId);
        // Generates a refresh token for a user, also with an optional session ID.
        // Refresh tokens are typically long-lived and used to obtain new access tokens without requiring re-authentication.
        string GenerateRefreshToken(User user, Guid? sessionId);
        // Extracts the claims principal from an expired token. This is often used during refresh token validation
        // to get user information from an expired access token (if the refresh token itself doesn't contain all necessary info).
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    }
}

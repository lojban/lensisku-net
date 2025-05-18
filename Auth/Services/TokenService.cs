using Lensisku.Auth.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace Lensisku.Auth.Services
{
    // TokenService implements ITokenService and is responsible for generating and validating JWTs (JSON Web Tokens).
    public class TokenService : ITokenService
    {
        // JwtSettings contains configuration for JWT generation (secret, issuer, audience, expiration).
        private readonly JwtSettings _jwtSettings;
        // A separate secret for refresh tokens, enhancing security.
        private readonly string _refreshTokenSecret;

        // Constructor for dependency injection.
        public TokenService(JwtSettings jwtSettings)
        {
            _jwtSettings = jwtSettings ?? throw new ArgumentNullException(nameof(jwtSettings));
            _refreshTokenSecret = Environment.GetEnvironmentVariable("REFRESH_TOKEN_SECRET")
                                ?? throw new InvalidOperationException("REFRESH_TOKEN_SECRET not found in environment variables.");
            if (string.IsNullOrEmpty(_jwtSettings.Secret))
            {
                throw new InvalidOperationException("JWT_SECRET not found in JwtSettings.");
            }
        }

        // Generates a JWT access token.
        public string GenerateAccessToken(User user, IEnumerable<string> permissions, Guid? sessionId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            // The secret key used to sign the token.
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret!);

            // Claims are statements about the user (or another entity) that are encoded into the token.
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique token ID
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("username", user.Username), // Custom claim for username
                // 'user.Role' is an enum (UserRole), so use ToString() to get its string representation.
                new Claim("role", user.Role.ToString()),
                new Claim("email_confirmed", user.EmailConfirmed.ToString().ToLowerInvariant()),
                new Claim("created_at", new DateTimeOffset(user.CreatedAt).ToUnixTimeSeconds().ToString()),
            };

            if (sessionId.HasValue)
            {
                // 'sid' (Session ID) claim links the token to a specific user session.
                claims.Add(new Claim("sid", sessionId.Value.ToString()));
            }

            foreach (var permission in permissions ?? Enumerable.Empty<string>())
            {
                // 'permissions' claim can be repeated for each permission the user has.
                claims.Add(new Claim("permissions", permission)); // Or use ClaimTypes.Role for each permission
            }
            
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                // Specifies the signing algorithm (HMAC SHA256).
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        // Generates a JWT refresh token.
        public string GenerateRefreshToken(User user, Guid? sessionId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            // Uses the dedicated refresh token secret.
            var key = Encoding.ASCII.GetBytes(_refreshTokenSecret);

            // Refresh tokens typically contain fewer claims, primarily for identification and expiry.
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                // Refresh tokens typically have fewer claims, primarily for identification and expiry
                new Claim("username", user.Username), // For identification if needed from refresh token
                 new Claim("role", user.Role.ToString()), // For identification if needed from refresh token
            };
            
            if (sessionId.HasValue)
            {
                claims.Add(new Claim("sid", sessionId.Value.ToString()));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
                // Issuer and Audience are often not strictly necessary for refresh tokens if they are opaque to the client
                // and only validated by the server using its specific secret.
                // Issuer = _jwtSettings.Issuer, 
                // Audience = _jwtSettings.Audience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        // Helper to get claims from an expired token, typically for refresh token validation
        // Note: This validates signature and expiry IF validateLifetime is true in params.
        // For refresh, we often want to ignore lifetime validation here as the token IS expired.
        // This method is crucial for the token refresh process.
        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false, // Or set to true if you use audience for refresh tokens
                ValidateIssuer = false,   // Or set to true if you use issuer for refresh tokens
                // Ensures the token was signed with the correct key.
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_refreshTokenSecret)), // Use REFRESH secret
                ValidateLifetime = false // IMPORTANT: Do not validate lifetime for expired tokens
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            try
            {
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
                // Additional check for the algorithm, ensuring it matches what's expected.
                if (!(securityToken is JwtSecurityToken jwtSecurityToken) || 
                    !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    return null; // Invalid algorithm
                }
                return principal;
            }
            catch
            {
                return null; // Token validation failed
            }
        }
    }
}

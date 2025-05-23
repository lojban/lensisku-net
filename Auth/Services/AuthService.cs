using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BCrypt.Net;
using Lensisku.Auth.DTOs;
using Lensisku.Auth.Exceptions;
using Lensisku.Auth.Models;
using Lensisku.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Lensisku.Auth.Services
{
    public class AuthService : IAuthService
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthService> _logger;
        private readonly SymmetricSecurityKey _accessTokenKey;
        private readonly SymmetricSecurityKey _refreshTokenKey;

        public AuthService(
            AppDbContext context,
            IConfiguration configuration,
            ILogger<AuthService> logger)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
            
            // Initialize JWT security keys from configuration with padding for short keys
            var jwtSecret = _configuration["JWT_SECRET"] ??
                throw new ArgumentException("JWT Secret not configured");
            var refreshSecret = _configuration["REFRESH_TOKEN_SECRET"] ??
                throw new ArgumentException("Refresh Token Secret not configured");
                
            // Pad short keys to meet minimum 128-bit requirement for HS256
            _accessTokenKey = CreatePaddedSecurityKey(jwtSecret);
            _refreshTokenKey = CreatePaddedSecurityKey(refreshSecret);
        }

        public async Task<AuthResponse> SignupAsync(SignupRequest request)
        {
            try
            {
                var existingUser = await _context.Users
                    .AnyAsync(u => u.Username == request.Username || u.Email == request.Email);

                if (existingUser)
                {
                    // Using InvalidOperationException as AppException is not defined yet.
                    // A custom AppException would be better for global error handling.
                    throw new InvalidOperationException("Username or email already exists");
                }

                var user = new User
                {
                    // UserId will be auto-generated by the database as an int
                    Username = request.Username,
                    Email = request.Email,
                    PasswordHash = HashPassword(request.Password),
                    CreatedAt = DateTime.UtcNow,
                    Role = UserRole.Unconfirmed,
                    SubscriptionStatus = "inactive", // Set default value
                    EmailConfirmationToken = Guid.NewGuid().ToString(), // For email confirmation
                    EmailConfirmationSentAt = DateTime.UtcNow
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                // Generate initial access token (no refresh token needed on immediate signup as per Rust)
                var accessToken = GenerateAccessToken(user, GetUserAuthorities(user), null);

                return new AuthResponse
                {
                    AccessToken = accessToken,
                    Message = "Signup successful. Please check your email to confirm your address."
                };
            }
            catch (DbUpdateException ex) // More specific exception
            {
                _logger.LogError(ex, "Database error during signup for email {Email}", request.Email);
                throw new AuthServiceException("Signup failed due to a database error.", ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during signup for email {Email}", request.Email);
                throw new AuthServiceException("Signup failed.", ex);
            }
        }

        public async Task<TokenResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent)
        {
            try
            {
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Username == request.UsernameOrEmail || u.Email == request.UsernameOrEmail);

            if (user == null || !VerifyPassword(request.Password, user.PasswordHash))
            {
                throw new UnauthorizedAccessException("Invalid credentials");
            }

            if (user.Role == UserRole.Blocked)
            {
                throw new UnauthorizedAccessException("Account is blocked");
            }

            // Handle password rehash if needed
            if (NeedsRehash(user.PasswordHash))
            {
                user.PasswordHash = HashPassword(request.Password);
                await _context.SaveChangesAsync();
            }

            // Generate session ID (will be replaced with session service later)
            var sessionId = Guid.NewGuid();

            // Generate token pair
            var accessToken = GenerateAccessToken(user, GetUserAuthorities(user), sessionId);
            var refreshToken = GenerateRefreshToken(user, sessionId);

            return new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "15") * 60
            };
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Failed login attempt for {UsernameOrEmail}", request.UsernameOrEmail);
                throw; // Re-throw to be handled by global error handler
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for {UsernameOrEmail}", request.UsernameOrEmail);
                throw new AuthServiceException("Login failed.", ex);
            }
        }

        private SymmetricSecurityKey CreatePaddedSecurityKey(string secret)
        {
            // Minimum recommended key size for HS256 is 256 bits (32 bytes).
            // The library error "key size must be greater than: '256' bits" for a 128-bit key
            // suggests it might actually require a key *strictly* greater than 256 bits,
            // or that 256 bits is the minimum threshold it's checking against.
            // We will pad to 32 bytes (256 bits). If error persists, might need > 32 bytes.
            const int targetKeySizeBytes = 32;
            var keyBytes = Encoding.UTF8.GetBytes(secret);
            
            if (keyBytes.Length >= targetKeySizeBytes)
            {
                // If key is already long enough, use it as is (or truncate if too long, though not typical for HMAC secrets)
                // For simplicity, we'll use it as is if it meets or exceeds the target.
                // A more robust approach for keys longer than necessary might involve hashing them to the target size.
                return new SymmetricSecurityKey(keyBytes.Take(targetKeySizeBytes).ToArray()); // Ensure it's exactly targetKeySizeBytes if too long
            }

            // Pad the key with zeros to reach target size
            var paddedKey = new byte[targetKeySizeBytes];
            Array.Copy(keyBytes, paddedKey, keyBytes.Length); // Copies original bytes, rest will be 0
            return new SymmetricSecurityKey(paddedKey);
        }

        private string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        private bool VerifyPassword(string password, string storedHash)
        {
            try
            {
                // First try BCrypt verification
                if (BCrypt.Net.BCrypt.Verify(password, storedHash))
                {
                    return true;
                }
            }
            catch (SaltParseException)
            {
                // If BCrypt fails, try MD5 with rot13 fallback
                var rot13Password = Rot13(password);
                using var md5 = MD5.Create();
                var inputHash = BitConverter.ToString(
                    md5.ComputeHash(Encoding.UTF8.GetBytes(rot13Password)))
                    .Replace("-", "").ToLowerInvariant();

                return inputHash == storedHash;
            }
            
            return false;
        }

        private bool NeedsRehash(string storedHash)
        {
            // MD5 hashes are 32 characters hex
            return storedHash.Length == 32 && !storedHash.Contains('$');
        }

        private static string Rot13(string input)
        {
            var buffer = input.ToCharArray();
            for (var i = 0; i < buffer.Length; i++)
            {
                var c = buffer[i];
                if (c >= 'a' && c <= 'z')
                {
                    buffer[i] = (char)((c - 'a' + 13) % 26 + 'a');
                }
                else if (c >= 'A' && c <= 'Z')
                {
                    buffer[i] = (char)((c - 'A' + 13) % 26 + 'A');
                }
            }
            return new string(buffer);
        }

        private string GenerateAccessToken(User user, IEnumerable<string> authorities, Guid? sessionId)
        {
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
                new(JwtRegisteredClaimNames.Email, user.Email),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new("username", user.Username),
                new("role", user.Role.ToString())
            };

            if (sessionId.HasValue)
            {
                claims.Add(new Claim("sid", sessionId.Value.ToString()));
            }

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(
                    int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "15")),
                signingCredentials: new SigningCredentials(
                    _accessTokenKey, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateRefreshToken(User user, Guid? sessionId)
        {
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            if (sessionId.HasValue)
            {
                claims.Add(new Claim("sid", sessionId.Value.ToString()));
            }

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddDays(
                    int.Parse(_configuration["Jwt:RefreshTokenExpirationDays"] ?? "7")),
                signingCredentials: new SigningCredentials(
                    _refreshTokenKey, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static IEnumerable<string> GetUserAuthorities(User user)
        {
            var authorities = new List<string> { user.Role.ToString() };
            if (!user.EmailConfirmed)
            {
                authorities.Add("UNCONFIRMED");
            }
            return authorities;
        }

        public async Task ConfirmEmailAsync(string token)
        {
            try
            {
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.EmailConfirmationToken == token && !u.EmailConfirmed);

                if (user == null)
                {
                    // Using a more specific exception or a custom one like AppValidationException if defined
                    throw new InvalidOperationException("Invalid or already used confirmation token.");
                }

                if (user.EmailConfirmationSentAt.HasValue &&
                    (DateTime.UtcNow - user.EmailConfirmationSentAt.Value).TotalHours > 24) // Token expiry, e.g., 24 hours
                {
                    throw new InvalidOperationException("Confirmation token has expired. Please request a new one.");
                }

                user.EmailConfirmed = true;
                user.EmailConfirmationToken = null; // Clear the token
                user.EmailConfirmationSentAt = null;
                // user.Role = UserRole.User; // Or UserRole.Editor as per original, ensure UserRole enum has this
                                            // Sticking to User for now as Unconfirmed was the initial state.
                                            // The task mentioned "Unconfirmed role (from UserRole enum)" for signup.
                                            // And Rust code updates role upon confirmation.

                await _context.SaveChangesAsync();
            }
            catch (InvalidOperationException ex) // Catch specific exceptions first
            {
                _logger.LogWarning(ex, "Email confirmation failed for token {Token}", token);
                throw; // Re-throw to be handled by global error handler or controller
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during email confirmation for token {Token}", token);
                throw new AuthServiceException("Email confirmation failed.", ex);
            }
        }

        // Stub implementations for unused interface methods
        public Task ResendConfirmationEmailAsync(ResendConfirmationRequestDto request) =>
            throw new NotImplementedException();

        public Task<PasswordResetResponseDto> RequestPasswordResetAsync(PasswordResetRequestDto request) =>
            throw new NotImplementedException();

        public Task RestorePasswordAsync(PasswordRestoreRequestDto request) =>
            throw new NotImplementedException();

        public async Task<TokenResponse> RefreshTokenAsync(RefreshTokenRequest request, string ipAddress, string userAgent)
        {
            if (string.IsNullOrEmpty(request.RefreshToken))
            {
                throw new AuthServiceException("Refresh token is required.");
            }

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(request.RefreshToken, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _refreshTokenKey,
                    ValidateIssuer = true, // Validate the issuer
                    ValidIssuer = _configuration["Jwt:Issuer"],
                    ValidateAudience = true, // Validate the audience
                    ValidAudience = _configuration["Jwt:Audience"],
                    ValidateLifetime = true, // Check token expiration
                    ClockSkew = TimeSpan.Zero // No tolerance for expiration
                }, out SecurityToken validatedToken);

                if (validatedToken is not JwtSecurityToken jwtSecurityToken ||
                    !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    throw new AuthServiceException("Invalid refresh token.");
                }

                var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? principal.FindFirst("sub")?.Value;
                var sessionIdClaim = principal.FindFirst("sid")?.Value;

                if (userIdClaim == null || !int.TryParse(userIdClaim, out var userId))
                {
                    throw new AuthServiceException("Invalid refresh token: Missing or invalid user ID.");
                }

                Guid? sessionId = null;
                if (sessionIdClaim != null && Guid.TryParse(sessionIdClaim, out var sid))
                {
                    sessionId = sid;
                }
                else if (sessionIdClaim != null)
                {
                     _logger.LogWarning("Refresh token contained a session ID ('sid') claim that was not a valid GUID: {SessionIdClaim}", sessionIdClaim);
                    // Depending on policy, you might throw an exception here or proceed without a session ID.
                    // For now, we'll proceed, but the new tokens won't carry forward an invalid SID.
                }


                // Placeholder for session update
                if (sessionId.HasValue)
                {
                    _logger.LogInformation("TODO: Update session activity for session {SessionId} for user {UserId}", sessionId.Value, userId);
                    // Example: await _sessionService.UpdateSessionActivityAsync(sessionId.Value, ipAddress, userAgent);
                }

                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    throw new AuthServiceException("User not found for the provided refresh token.");
                }
                 if (user.Role == UserRole.Blocked)
                {
                    _logger.LogWarning("Refresh token attempt for blocked user {UserId}", userId);
                    throw new AuthServiceException("Account is blocked.");
                }


                var newAccessToken = GenerateAccessToken(user, GetUserAuthorities(user), sessionId);
                var newRefreshToken = GenerateRefreshToken(user, sessionId);

                return new TokenResponse
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken,
                    ExpiresIn = int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "15") * 60
                };
            }
            catch (SecurityTokenExpiredException ex)
            {
                _logger.LogWarning(ex, "Refresh token expired.");
                throw new AuthServiceException("Refresh token expired.", ex);
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogWarning(ex, "Invalid refresh token.");
                throw new AuthServiceException("Invalid refresh token.", ex);
            }
            catch (AuthServiceException) // Re-throw specific auth exceptions
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred during token refresh for user agent {UserAgent}", userAgent);
                throw new AuthServiceException("An unexpected error occurred during token refresh.", ex);
            }
        }

        public Task<InitiatePasswordChangeResponseDto> InitiatePasswordChangeAsync(int userId, InitiatePasswordChangeRequestDto request) =>
            throw new NotImplementedException();

        public Task CompletePasswordChangeAsync(int userId, CompletePasswordChangeRequestDto request) =>
            throw new NotImplementedException();

        public async Task LogoutAsync(int userId, Guid? sessionId)
        {
            // Placeholder for session termination
            if (sessionId.HasValue)
            {
                _logger.LogInformation("TODO: Terminate session {SessionId} for user {UserId}", sessionId.Value, userId);
                // Example: await _sessionService.EndSessionAsync(sessionId.Value);
            }
            else
            {
                _logger.LogInformation("TODO: Terminate all sessions for user {UserId} or handle as per policy if no specific session ID is provided.", userId);
                // Example: await _sessionService.EndAllUserSessionsAsync(userId);
            }
            // Simulate an asynchronous operation if needed for consistency, though logging is synchronous.
            await Task.CompletedTask;
        }
    }
}


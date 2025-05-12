using Lensisku.Auth.DTOs;
using Lensisku.Auth.Models;
using Lensisku.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Cryptography; // For random token generation if needed beyond Guid
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace Lensisku.Auth.Services
{
    // AuthService implements IAuthService and contains the core business logic for authentication processes
    // such as signup, login, email confirmation, password reset, token refresh, and logout.
    // It orchestrates interactions between various components like DbContext, PasswordHasher, TokenService, EmailService, and UserSessionService.
    public class AuthService : IAuthService
    {
        private readonly AppDbContext _context;
        private readonly IPasswordHasherService _passwordHasher;
        private readonly ITokenService _tokenService;
        private readonly IEmailService _emailService; // Service for sending emails.
        private readonly IUserSessionService _userSessionService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            AppDbContext context,
            IPasswordHasherService passwordHasher,
            ITokenService tokenService,
            IEmailService emailService,
            IUserSessionService userSessionService,
            IConfiguration configuration, // Used to access application configuration settings.
            ILogger<AuthService> logger)
        {
            _context = context;
            _passwordHasher = passwordHasher;
            _tokenService = tokenService;
            _emailService = emailService;
            _userSessionService = userSessionService;
            _configuration = configuration;
            _logger = logger;
        }

        // Handles user signup.
        public async Task<(bool Success, TokenResponseDto? TokenResponse, string Message)> SignupAsync(SignupRequestDto signupRequest)
        {
            try
            {
                // Checks if a user with the same username or email already exists to prevent duplicates.
                // .AnyAsync() is an efficient way to check for existence.
                var existingUser = await _context.Users
                    .AnyAsync(u => u.Username == signupRequest.Username || u.Email == signupRequest.Email);

                if (existingUser)
                {
                    return (false, null, "Username or email already exists.");
                }

                // Retrieves the "Unconfirmed" role, which is assigned to newly registered users before email verification.
                var unconfirmedRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "Unconfirmed");
                if (unconfirmedRole == null)
                {
                    // This case should ideally not happen if roles are seeded.
                    // For robustness, could create it, or ensure it's part of initial setup.
                    _logger.LogError("Critical: 'Unconfirmed' role not found in database.");
                    return (false, null, "System configuration error: Unconfirmed role missing.");
                }

                // Creates a new User entity.
                var user = new User
                {
                    Username = signupRequest.Username,
                    Email = signupRequest.Email,
                    PasswordHash = _passwordHasher.HashPassword(signupRequest.Password),
                    CreatedAt = DateTime.UtcNow,
                    RoleId = unconfirmedRole.Id, // Assign 'Unconfirmed' role
                    Role = unconfirmedRole, // For token generation if it uses navigation property directly
                    EmailConfirmed = false,
                    EmailConfirmationToken = Guid.NewGuid().ToString(),
                    EmailConfirmationSentAt = DateTime.UtcNow,
                    VoteSize = 1.0f // Default
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();
                // Saves the new user to the database.

                // Prepares and sends an email confirmation link.
                var confirmationUrl = $"confirm-email?token={user.EmailConfirmationToken}";
                var emailContent = _emailService.BuildEmailContent(
                    new[] {
                        "Welcome to Lensisku!",
                        "Please confirm your email address to activate your account.",
                        "This link will expire in 24 hours.",
                        "",
                        "If you didn't create this account, please ignore this email."
                    },
                    ("Confirm Email", confirmationUrl)
                );
                
                // Not awaiting this to match Rust's async email sending
                _ = _emailService.SendEmailAsync(new EmailNotificationDto
                {
                    ToEmail = user.Email,
                    Subject = "Confirm your email address - Lensisku",
                    TextBody = emailContent.textBody,
                    HtmlBody = emailContent.htmlBody
                }).ContinueWith(t => {
                    if (t.IsFaulted) _logger.LogError(t.Exception, "Failed to send confirmation email for {UserEmail}", user.Email);
                });

                
                // To generate tokens, we need permissions. Unconfirmed users usually have none or very limited.
                // For now, pass empty list. Actual permissions will be based on their role post-confirmation.
                // Generates access and refresh tokens for the newly signed-up user.
                // Even unconfirmed users might get tokens, possibly with limited permissions.
                // The 'sid' (session ID) is null here as signup doesn't typically start a formal session immediately.

                // However, the return type is TokenResponseDto which has AccessToken and RefreshToken.
                // For now, let's return only an access token in the AccessToken field.
                // A better approach might be to not return tokens on signup, and require login after confirmation.
                // Or, return a limited-use token.
                // Given the DTO, let's return a full pair but maybe with limited permissions.
                
                // For an unconfirmed user, they don't have a session ID from login yet.
                // The JWT sid claim is for linking to an active user_sessions entry.
                // Signup doesn't create an active session in the Rust code.
                var tokenResponse = new TokenResponseDto
                {
                    AccessToken = _tokenService.GenerateAccessToken(user, new List<string> { "UNCONFIRMED_USER" }, null), // Minimal permission
                    RefreshToken = _tokenService.GenerateRefreshToken(user, null) // No active session yet
                };


                return (true, tokenResponse, "Signup successful. Please check your email to confirm your address.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during signup for email {Email}", signupRequest.Email);
                return (false, null, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Handles user login.
        public async Task<(bool Success, TokenResponseDto? TokenResponse, string Message)> LoginAsync(LoginRequestDto loginRequest, string ipAddress, string userAgent)
        {
            try
            {
                // Retrieves the user by username or email.
                // .Include(u => u.Role) eagerly loads the related Role entity, which is needed for role name and permissions.
                var user = await _context.Users
                    .Include(u => u.Role) // Include Role for role name and permissions
                    // This allows login with either username or email.
                    .FirstOrDefaultAsync(u => u.Username == loginRequest.UsernameOrEmail || u.Email == loginRequest.UsernameOrEmail);

                if (user == null)
                {
                    return (false, null, "Invalid credentials.");
                }

                // Checks if the user's account is blocked or disabled.
                if (user.Role.Name == "Blocked" || user.Disabled) // Check both Role name and Disabled flag
                {
                    return (false, null, "Account is blocked.");
                }

                // Verifies the provided password against the stored hash.
                if (!_passwordHasher.VerifyPassword(loginRequest.Password, user.PasswordHash))
                {
                    return (false, null, "Invalid credentials.");
                }

                // If the password hash uses an outdated algorithm, rehash it with the current one.
                bool rehashed = false;
                if (_passwordHasher.NeedsRehash(user.PasswordHash))
                {
                    user.PasswordHash = _passwordHasher.HashPassword(loginRequest.Password);
                    rehashed = true;
                    _logger.LogInformation("Password rehashed for user {UserId}", user.UserId);
                }

                // Start user session
                // Logs the user's session details (IP, user agent).
                UserSession? session = await _userSessionService.StartSessionAsync(user.UserId, ipAddress, userAgent);
                if (session == null)
                {
                    _logger.LogWarning("Failed to start session for user {UserId} during login, but proceeding with token generation.", user.UserId);
                }

                // Get permissions for the user's role
                // Fetches permissions associated with the user's role to include in the JWT.
                var permissions = await _context.RolePermissions
                    .Where(rp => rp.RoleId == user.RoleId)
                    .Include(rp => rp.Permission)
                    .Select(rp => rp.Permission.Name)
                    .ToListAsync();
                
                if (!user.EmailConfirmed)
                {
                    // Adds a special marker/permission if the user's email is not yet confirmed.
                    permissions.Add("UNCONFIRMED_USER"); // Add special permission if email not confirmed
                }

                // Generates new access and refresh tokens. The session's UUID is included as 'sid' claim in the tokens.
                var accessToken = _tokenService.GenerateAccessToken(user, permissions, session?.SessionUuid);
                var refreshToken = _tokenService.GenerateRefreshToken(user, session?.SessionUuid);

                if (rehashed)
                {
                    await _context.SaveChangesAsync(); // Save rehashed password
                }

                var tokenResponse = new TokenResponseDto
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                };

                return (true, tokenResponse, "Login successful.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for {UsernameOrEmail}", loginRequest.UsernameOrEmail);
                return (false, null, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Confirms a user's email address using a confirmation token.
        public async Task<(bool Success, string Message)> ConfirmEmailAsync(string token)
        {
            try
            {
                // Finds a user with the given token who has not yet confirmed their email.
                var user = await _context.Users
                    .Include(u => u.Role) // Include role to potentially update it or check current
                    // Ensures the token is valid and email is not already confirmed.
                    .FirstOrDefaultAsync(u => u.EmailConfirmationToken == token && !u.EmailConfirmed);

                if (user == null)
                {
                    return (false, "Invalid or already used confirmation token.");
                }

                // Checks if the confirmation token has expired (e.g., older than 24 hours).
                if (user.EmailConfirmationSentAt.HasValue &&
                    (DateTime.UtcNow - user.EmailConfirmationSentAt.Value).TotalHours > 24)
                {
                    // Optionally, resend a new token or instruct user to request a new one
                    // For now, just mark as expired.
                    // Consider deleting the expired token from user record or marking it as explicitly expired.
                    // user.EmailConfirmationToken = null;
                    // await _context.SaveChangesAsync();
                    return (false, "Confirmation token has expired. Please request a new one.");
                }

                // Retrieves the target role for confirmed users (e.g., "Editor").
                var editorRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "Editor");
                if (editorRole == null)
                {
                    _logger.LogError("Critical: 'Editor' role not found in database. Cannot upgrade user role on email confirmation.");
                    // Decide: proceed without role change, or fail? For now, fail as role change is part of spec.
                    return (false, "System configuration error: Target role for confirmed users is missing.");
                }

                // Updates user's status to email confirmed and clears confirmation token details.
                user.EmailConfirmed = true;
                user.EmailConfirmationToken = null;
                user.EmailConfirmationSentAt = null; // Clear the sent_at time as token is used/invalidated
                
                // Only change role if they are currently "Unconfirmed"
                if (user.Role?.Name == "Unconfirmed") // Check if Role is loaded and is "Unconfirmed"
                {
                    // Upgrades the user's role from "Unconfirmed" to the confirmed user role.
                    user.RoleId = editorRole.Id;
                    // EF Core should update user.Role navigation property if RoleId changes and Role was loaded.
                }
                
                await _context.SaveChangesAsync();
                _logger.LogInformation("Email confirmed for user {UserId}. Role updated if applicable.", user.UserId);
                return (true, "Email confirmed successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during email confirmation for token {Token}", token);
                return (false, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Resends an email confirmation link to a user.
        public async Task<(bool Success, string Message)> ResendConfirmationEmailAsync(ResendConfirmationRequestDto request)
        {
            try
            {
                // Finds the user by email.
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);

                if (user == null)
                {
                    // To prevent email enumeration, return a generic message even if user not found
                    _logger.LogInformation("Resend confirmation requested for non-existent email (or already confirmed): {Email}", request.Email);
                    return (true, "If your email address exists in our system and requires confirmation, a new confirmation email has been sent.");
                }

                // Checks if the email is already confirmed.
                if (user.EmailConfirmed)
                {
                    return (false, "This email address has already been confirmed.");
                }

                // Check for recent resend attempts (e.g., if EmailConfirmationSentAt is very recent)
                // This is a simple form of rate limiting. More robust rate limiting should be at API gateway or middleware.
                // Prevents spamming the resend functionality.
                if (user.EmailConfirmationSentAt.HasValue && (DateTime.UtcNow - user.EmailConfirmationSentAt.Value).TotalMinutes < 5) // Example: 5 min cooldown
                {
                    _logger.LogWarning("Resend confirmation attempt too soon for email: {Email}", request.Email);
                    return (false, "A confirmation email was recently sent. Please check your inbox or wait a few minutes before trying again.");
                }

                user.EmailConfirmationToken = Guid.NewGuid().ToString();
                // Generates a new confirmation token and updates its sent time.
                user.EmailConfirmationSentAt = DateTime.UtcNow;

                await _context.SaveChangesAsync();

                var confirmationUrl = $"confirm-email?token={user.EmailConfirmationToken}";
                // Prepares and sends the new confirmation email.
                 var emailContent = _emailService.BuildEmailContent(
                    new[] {
                        "Welcome back to Lensisku!",
                        "Please confirm your email address to activate your account by clicking the link below.",
                        "This link will expire in 24 hours.",
                        "",
                        "If you didn't request this, please ignore this email."
                    },
                    ("Confirm Your Email", confirmationUrl)
                );

                // Sends the email asynchronously without awaiting its completion (fire-and-forget).
                // Error handling for email sending is done in a continuation task.
                // Not awaiting this to match Rust's async email sending
                _ = _emailService.SendEmailAsync(new EmailNotificationDto
                {
                    ToEmail = user.Email,
                    Subject = "Resend: Confirm your email address - Lensisku",
                    TextBody = emailContent.textBody,
                    HtmlBody = emailContent.htmlBody
                }).ContinueWith(t => {
                    if (t.IsFaulted) _logger.LogError(t.Exception, "Failed to resend confirmation email for {UserEmail}", user.Email);
                });
                
                _logger.LogInformation("Resent confirmation email to {Email}", request.Email);
                return (true, "A new confirmation email has been sent to your email address. Please check your inbox.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resending confirmation email for {Email}", request.Email);
                return (false, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Initiates a password reset request for a user (typically when they've forgotten their password).
        public async Task<(bool Success, PasswordResetResponseDto? Response, string Message)> RequestPasswordResetAsync(PasswordResetRequestDto request)
        {
            // Implements a basic rate limiting check to prevent abuse of the password reset feature.
            // Basic rate limiting idea (can be enhanced with dedicated rate limiting service/middleware)
            var recentRequests = await _context.PasswordResetRequestLogs
                .Where(prr => prr.Email == request.Email && prr.CreatedAt > DateTime.UtcNow.AddMinutes(-15)) // e.g., 3 requests in 15 mins
                .CountAsync();
            
            if (recentRequests >= 3) // Limit to 3 requests per 15 minutes for an email
            {
                _logger.LogWarning("Password reset rate limit exceeded for email: {Email}", request.Email);
                // Return a generic success message to avoid leaking info, but internally it's rate limited.
                // The Rust version also returns success but might have a more robust limiter.
                return (true, new PasswordResetResponseDto { Success = true, Message = "If your email address is registered, you will receive a password reset link.", SessionId = null }, "Rate limit hit, generic message returned.");
            }

            try
            {
                // Checks if a user with the provided email exists.
                var userExists = await _context.Users.AnyAsync(u => u.Email == request.Email);
                
                // Always generate a session ID for the response DTO, even if user doesn't exist,
                // to make it harder to determine if an email is registered based on response structure.
                var sessionId = Guid.NewGuid().ToString();

                if (!userExists)
                {
                    _logger.LogInformation("Password reset requested for non-existent email: {Email}", request.Email);
                    // Return success to prevent email enumeration
                    return (true, new PasswordResetResponseDto { Success = true, Message = "If your email address is registered, you will receive a password reset link.", SessionId = sessionId }, "User not found, generic message returned.");
                }

                // Generates a unique, URL-safe token for the password reset link.
                var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace("+", "-").Replace("/", "_").TrimEnd('='); // URL-safe random token
                var tokenExpiryMinutes = _configuration.GetValue<int?>("JwtSettings:PasswordResetTokenExpiryMinutes") ?? 30; // Get from config or default
                var tokenExpiry = DateTime.UtcNow.AddMinutes(tokenExpiryMinutes);

                // Logs the password reset request.
                var resetLog = new PasswordResetRequestLog
                {
                    Email = request.Email,
                    SessionId = sessionId,
                    Token = token, // This token is for the URL, not a JWT
                    TokenExpiry = tokenExpiry,
                    CreatedAt = DateTime.UtcNow,
                    Used = false
                };

                _context.PasswordResetRequestLogs.Add(resetLog);
                await _context.SaveChangesAsync();

                var resetUrl = $"reset-password?token={token}&session_id={sessionId}";
                // Prepares and sends the password reset email.
                var emailContent = _emailService.BuildEmailContent(
                     new[] {
                        "We received a request to reset your password for your Lensisku account.",
                        $"Please click the link below to set a new password. This link will expire in {tokenExpiryMinutes} minutes.",
                        "",
                        "If you didn't request this change, you can safely ignore this email."
                    },
                    ("Reset Your Password", resetUrl)
                );

                _ = _emailService.SendEmailAsync(new EmailNotificationDto
                {
                    ToEmail = request.Email,
                    Subject = "Lensisku - Password Reset Request",
                    TextBody = emailContent.textBody,
                    HtmlBody = emailContent.htmlBody
                }).ContinueWith(t => {
                    if (t.IsFaulted) _logger.LogError(t.Exception, "Failed to send password reset email for {UserEmail}", request.Email);
                });

                _logger.LogInformation("Password reset email sent to {Email}", request.Email);
                return (true, new PasswordResetResponseDto { Success = true, Message = "Password reset email sent successfully.", SessionId = sessionId }, "Password reset email sent.");

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error requesting password reset for {Email}", request.Email);
                // Return a generic message even on internal error for security, but log details.
                return (false, null, $"An unexpected error occurred. Please try again later.");
            }
        }

        // Completes the password reset process using the token and session ID from the reset link.
        public async Task<(bool Success, string Message)> RestorePasswordAsync(PasswordRestoreRequestDto request)
        {
            try
            {
                // Validates the provided token and session ID against the logged requests.
                var resetRequestLog = await _context.PasswordResetRequestLogs
                    .FirstOrDefaultAsync(prr => prr.SessionId == request.SessionId && prr.Token == request.Token);

                if (resetRequestLog == null)
                {
                    return (false, "Invalid or expired password reset token/session.");
                }

                // Checks if the token has already been used.
                if (resetRequestLog.Used)
                {
                    return (false, "This password reset link has already been used.");
                }

                // Checks if the token has expired.
                if (resetRequestLog.TokenExpiry < DateTime.UtcNow)
                {
                    return (false, "This password reset link has expired.");
                }

                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == resetRequestLog.Email);
                if (user == null)
                {
                    // Should not happen if resetRequestLog is valid and email hasn't changed, but good to check.
                    _logger.LogError("User not found for a valid password reset log. Email: {Email}", resetRequestLog.Email);
                    return (false, "User associated with this reset request not found.");
                }

                // Updates the user's password with the new one (after hashing it).
                user.PasswordHash = _passwordHasher.HashPassword(request.NewPassword);
                resetRequestLog.Used = true;
                // Marks the reset token as used.
                resetRequestLog.UsedAt = DateTime.UtcNow;

                await _context.SaveChangesAsync();
                _logger.LogInformation("Password restored for user {UserId} via email {Email}", user.UserId, user.Email);
                return (true, "Your password has been reset successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error restoring password for session ID {SessionId}", request.SessionId);
                return (false, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Refreshes access and refresh tokens using a valid refresh token.
        public async Task<(bool Success, TokenResponseDto? TokenResponse, string Message)> RefreshTokensAsync(string refreshToken, string ipAddress, string userAgent)
        {
            try
            {
                // Validates the refresh token and extracts the user principal (claims) from it.
                // GetPrincipalFromExpiredToken is used because the refresh token itself might be a JWT that's validated, or it might be used to validate an expired access token.
                var principal = _tokenService.GetPrincipalFromExpiredToken(refreshToken);
                if (principal == null)
                {
                    _logger.LogWarning("Refresh token validation failed or principal could not be extracted.");
                    return (false, null, "Invalid refresh token.");
                }

                // Extracts user ID and session ID (sid) from the token's claims.
                // Standard claim for user ID in JWT is Subject (sub) or NameIdentifier
                var userIdString = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value ??
                                   principal.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;

                if (!int.TryParse(userIdString, out var userId))
                {
                    _logger.LogError("User ID claim (sub/nameidentifier) missing or invalid in refresh token principal.");
                    return (false, null, "Invalid user identifier in refresh token.");
                }
                
                var sidClaim = principal.Claims.FirstOrDefault(c => c.Type == "sid")?.Value;
                Guid? sessionUuid = null;
                if (Guid.TryParse(sidClaim, out var parsedSid))
                {
                    sessionUuid = parsedSid;
                }

                // If a session ID is present, update the corresponding user session's activity.
                if (sessionUuid.HasValue)
                {
                    var dbSessionId = await _userSessionService.GetSessionIdFromUuidAsync(sessionUuid.Value);
                    if (dbSessionId.HasValue)
                    {
                        var updatedSession = await _userSessionService.UpdateSessionActivityAsync(userId, dbSessionId.Value, ipAddress, userAgent);
                        if (updatedSession == null)
                        {
                             _logger.LogWarning("Failed to update session activity for SID {SessionUuid} (DB ID: {DbSessionId}) during token refresh, but proceeding.", sessionUuid.Value, dbSessionId.Value);
                        }
                    }
                    else
                    {
                        _logger.LogWarning("No active DB session found for SID {SessionUuid} from refresh token during token refresh. New tokens will retain this SID if present.", sessionUuid.Value);
                    }
                }
                else
                {
                     _logger.LogInformation("No SID found in refresh token for user {UserId}. Cannot update session activity.", userId);
                }

                // Retrieves the user from the database.
                var user = await _context.Users.Include(u => u.Role).FirstOrDefaultAsync(u => u.UserId == userId);
                if (user == null)
                {
                    _logger.LogError("User {UserId} associated with refresh token not found in DB.", userId);
                    return (false, null, "User associated with refresh token not found.");
                }

                // Checks if the user account is blocked or disabled.
                if (user.Role.Name == "Blocked" || user.Disabled)
                {
                     _logger.LogWarning("Attempt to refresh token for blocked/disabled user {UserId}.", userId);
                    return (false, null, "Account is blocked or disabled.");
                }

                var permissions = await _context.RolePermissions
                    // Fetches the user's current permissions for the new access token.
                    .Where(rp => rp.RoleId == user.RoleId)
                    .Include(rp => rp.Permission)
                    .Select(rp => rp.Permission.Name)
                    .ToListAsync();
                
                if (!user.EmailConfirmed)
                {
                    permissions.Add("UNCONFIRMED_USER");
                }

                // Generates new access and refresh tokens, preserving the original session ID if present.
                var newAccessToken = _tokenService.GenerateAccessToken(user, permissions, sessionUuid); // Pass original sessionUuid
                var newRefreshToken = _tokenService.GenerateRefreshToken(user, sessionUuid); // Pass original sessionUuid

                var tokenResponse = new TokenResponseDto
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken
                };
                _logger.LogInformation("Tokens refreshed successfully for user {UserId}", userId);
                return (true, tokenResponse, "Tokens refreshed successfully.");
            }
            catch (SecurityTokenException secEx)
            {
                _logger.LogWarning(secEx, "Security token exception during token refresh: {ErrorMessage}", secEx.Message);
                return (false, null, "Invalid refresh token.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token refresh.");
                return (false, null, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Initiates a password change process for an authenticated user.
        public async Task<(bool Success, InitiatePasswordChangeResponseDto? Response, string Message)> InitiatePasswordChangeAsync(int userId, InitiatePasswordChangeRequestDto request)
        {
            try
            {
                // Verifies the user's current password.
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return (false, null, "User not found.");
                }

                if (!_passwordHasher.VerifyPassword(request.CurrentPassword, user.PasswordHash))
                {
                    return (false, null, "Invalid current password.");
                }

                // Generates a verification ID and a short code (e.g., 6-digit).
                var verificationId = Guid.NewGuid().ToString();
                // Generate a 6-digit code for simplicity, similar to many 2FA systems
                var verificationCode = new Random().Next(100000, 999999).ToString();
                var expiresAt = DateTime.UtcNow.AddMinutes(_configuration.GetValue<int?>("JwtSettings:PasswordChangeVerificationExpiryMinutes") ?? 30);

                // Logs the password change verification attempt.
                var verificationLog = new PasswordChangeVerification
                {
                    UserId = userId,
                    VerificationId = verificationId,
                    VerificationCode = verificationCode,
                    ExpiresAt = expiresAt,
                    CreatedAt = DateTime.UtcNow
                };

                _context.PasswordChangeVerifications.Add(verificationLog);
                await _context.SaveChangesAsync();

                // Sends the verification code to the user's email.
                var emailContent = _emailService.BuildEmailContent(
                    new[] {
                        "You requested to change your password for Lensisku.",
                        $"Your verification code is: {verificationCode}",
                        $"This code will expire in {(_configuration.GetValue<int?>("JwtSettings:PasswordChangeVerificationExpiryMinutes") ?? 30)} minutes.",
                        "",
                        "If you didn't request this change, please ignore this email or contact support if you suspect unauthorized activity."
                    },
                    null // No call to action link, code is in the body
                );

                _ = _emailService.SendEmailAsync(new EmailNotificationDto
                {
                    ToEmail = user.Email,
                    Subject = "Lensisku - Password Change Verification Code",
                    TextBody = emailContent.textBody,
                    HtmlBody = emailContent.htmlBody
                }).ContinueWith(t => {
                    if (t.IsFaulted) _logger.LogError(t.Exception, "Failed to send password change verification email for user {UserId}", userId);
                });
                
                _logger.LogInformation("Password change initiated for user {UserId}. Verification ID: {VerificationId}", userId, verificationId);
                return (true, new InitiatePasswordChangeResponseDto { Message = "Verification code sent to your email.", VerificationId = verificationId }, "Verification code sent.");

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initiating password change for user {UserId}", userId);
                return (false, null, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Completes the authenticated password change process using the verification ID and code.
        public async Task<(bool Success, string Message)> CompletePasswordChangeAsync(int userId, CompletePasswordChangeRequestDto request)
        {
            try
            {
                // Validates the verification ID and code.
                var verificationLog = await _context.PasswordChangeVerifications
                    .FirstOrDefaultAsync(v => v.UserId == userId &&
                                            v.VerificationId == request.VerificationId &&
                                            v.VerificationCode == request.VerificationCode &&
                                            v.CompletedAt == null);

                if (verificationLog == null)
                {
                    return (false, "Invalid or already used verification code/ID.");
                }

                // Checks if the verification code has expired.
                if (verificationLog.ExpiresAt < DateTime.UtcNow)
                {
                    return (false, "Verification code has expired.");
                }

                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    _logger.LogError("User {UserId} not found for a valid password change verification log. This should not happen.", userId);
                    return (false, "User not found, though verification was valid. Please contact support.");
                }

                // Updates the user's password.
                user.PasswordHash = _passwordHasher.HashPassword(request.NewPassword);
                verificationLog.CompletedAt = DateTime.UtcNow;
                // Marks the verification log as completed.

                // Security consideration: Invalidate other active sessions for the user.
                // This would involve finding all UserSession entries for this userId where EndedAt is null
                // and setting their EndedAt. This is a common practice after password changes.
                // Example (can be extracted to UserSessionService):
                var activeSessions = await _context.UserSessions
                    .Where(s => s.UserId == userId && s.EndedAt == null)
                    .ToListAsync();
                

                // Ends all other active sessions for the user as a security measure.
                foreach (var session in activeSessions)
                {
                    session.EndedAt = DateTime.UtcNow;
                    _logger.LogInformation("Invalidated active session {SessionUuid} for user {UserId} due to password change.", session.SessionUuid, userId);
                }

                await _context.SaveChangesAsync();
                _logger.LogInformation("Password successfully changed for user {UserId}", userId);
                return (true, "Password changed successfully. Any other active sessions have been logged out.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error completing password change for user {UserId}", userId);
                return (false, $"An unexpected error occurred: {ex.Message}");
            }
        }
        
        // Handles user logout.
        public async Task<(bool Success, string Message)> LogoutAsync(int userId, Guid? sessionId)
        {
            try
            {
                // If a specific session ID is provided (from JWT 'sid' claim), end that session.
                if (!sessionId.HasValue)
                {
                    // If no session ID is provided from the token, try to end any active session for the user.
                    // This matches the behavior if Rust's end_session only took user_id.
                    _logger.LogInformation("Logout called for user {UserId} without a specific session ID. Attempting to end general active session.", userId);
                    var ended = await _userSessionService.EndUserActiveSessionAsync(userId);
                    return ended
                        ? (true, "Logout successful. Active session ended.")
                        : (false, "Logout processed, but no active session was found to end or an error occurred.");
                }

                // Calls the user session service to end the specified session.
                var success = await _userSessionService.EndSessionAsync(userId, sessionId.Value);
                if (success)
                {
                    _logger.LogInformation("Logout successful for user {UserId}, session {SessionId}", userId, sessionId.Value);
                    return (true, "Logout successful.");
                }
                else
                {
                    _logger.LogWarning("Logout failed for user {UserId}, session {SessionId} (session not found or already ended).", userId, sessionId.Value);
                    // Still return a "successful" logout from client perspective if session simply wasn't active.
                    return (true, "Logout processed. Session was not active or not found.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout for user {UserId}, session {SessionId}", userId, sessionId);
                return (false, $"An unexpected error occurred during logout: {ex.Message}");
            }
        }
    }
}

// This 'using' directive imports namespaces, making types within them accessible without full qualification.
using Lensisku.Auth.DTOs; // Ensure all new DTOs are covered if not already
using Lensisku.Auth.Services;
using Lensisku.Auth.Exceptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
// For IFormFile (file uploads) and StatusCodes (HTTP status code constants).
using Microsoft.AspNetCore.Http; 
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
// For JwtRegisteredClaimNames, standard claim type names for JWTs.
using System.IdentityModel.Tokens.Jwt; 

// Namespaces are used to organize code and prevent naming conflicts.
// This namespace follows a common convention: ProjectName.ModuleName.ComponentType.
namespace Lensisku.Auth.Controllers
{
    // [ApiController] attribute enables API-specific behaviors like automatic model validation and problem details for errors.
    [ApiController]
    // [Route] attribute defines the base route for all actions in this controller.
    // "api/[controller]" uses a token "[controller]" which is replaced by the controller name ("Auth" in this case).
    // So, the base route will be "api/auth".
    [Route("api/[controller]")] 
    // Controllers handle incoming HTTP requests, process them (often by calling services), and return HTTP responses.
    // ControllerBase is a base class for MVC controllers without view support, suitable for APIs.
    public class AuthController : ControllerBase
    {
        // Private readonly fields for dependency injection. 'readonly' means they can only be assigned in the constructor.
        private readonly IAuthService _authService;
        private readonly IUserService _userService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IAuthService authService,
            // This constructor demonstrates Dependency Injection (DI).
            // ASP.NET Core's built-in DI container provides instances of IAuthService, IUserService, etc.
            // This promotes loose coupling and testability.
            IUserService userService,
            ILogger<AuthController> logger)
        {
            _authService = authService;
            _userService = userService;
            _logger = logger;
        }

        // Helper to get current user's ID from claims
        // Claims are pieces of information (e.g., user ID, roles, permissions) asserted about a subject (user),
        // typically embedded in a JWT token after successful authentication.
        protected int GetCurrentUserId()
        {
            var userIdClaim = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value ??
                              User.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
            if (int.TryParse(userIdClaim, out var userId))
            {
                return userId;
            }
            // This should not happen if [Authorize] is used correctly with a valid token
            throw new InvalidOperationException("User ID not found or invalid integer format in token claims.");
        }

        // Helper to get current user's Role Name from claims
        // This demonstrates accessing custom claims ("role") in addition to standard ones.
        // This demonstrates accessing custom claims ("role") in addition to standard ones.
        protected string GetCurrentUserRoleName()
        {
             var roleClaim = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value ??
                             User.Claims.FirstOrDefault(c => c.Type == "role")?.Value; // "role" is custom claim from TokenService
            if (!string.IsNullOrEmpty(roleClaim))
            {
                return roleClaim;
            }
            throw new InvalidOperationException("User role not found in token claims.");
        }

        // [AllowAnonymous] attribute allows access to this endpoint without authentication.
        [AllowAnonymous]
        // [HttpPost("signup")] attribute maps HTTP POST requests to "api/auth/signup" to this action method.
        [HttpPost("signup")]
        // [ProducesResponseType] attributes inform Swagger/OpenAPI about the types of responses this action can return,
        // including success (200 OK with TokenResponseDto) and various error types (409, 400, 500 with ProblemDetails).
        // This is crucial for API documentation and client generation.
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)] // Updated DTO
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)] // For username/email exists
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For validation errors
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> Signup([FromBody] SignupRequest signupRequest) // Updated DTO
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                var authResponse = await _authService.SignupAsync(signupRequest);
                return Ok(authResponse);
            }
            catch (AuthServiceException ex)
            {
                _logger.LogWarning(ex, "Signup failed for user {Username}: {Message}", signupRequest.Username, ex.Message);
                if (ex.Message.Contains("already exists", StringComparison.OrdinalIgnoreCase))
                {
                    return Conflict(new ProblemDetails { Title = "Signup Failed", Detail = ex.Message, Status = StatusCodes.Status409Conflict });
                }
                // Default to 400 Bad Request for other auth service related signup errors
                return BadRequest(new ProblemDetails { Title = "Signup Error", Detail = ex.Message, Status = StatusCodes.Status400BadRequest });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during signup for user {Username}", signupRequest.Username);
                return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Signup Error", Detail = "An unexpected error occurred." });
            }
        }

        [AllowAnonymous]
        [HttpPost("login")]
        [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)] // Updated DTO
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest) // Updated DTO
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var userAgent = Request.Headers["User-Agent"].ToString() ?? "unknown";

            try
            {
                var tokenResponse = await _authService.LoginAsync(loginRequest, ipAddress, userAgent);
                return Ok(tokenResponse);
            }
            catch (AuthServiceException ex)
            {
                _logger.LogWarning(ex, "Login failed for {UsernameOrEmail}: {Message}", loginRequest.UsernameOrEmail, ex.Message);
                // Check message for specific login failure reasons
                if (ex.Message.Contains("Invalid credentials", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("Account is blocked", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("Email not confirmed", StringComparison.OrdinalIgnoreCase))
                {
                    return Unauthorized(new ProblemDetails { Title = "Login Failed", Detail = ex.Message, Status = StatusCodes.Status401Unauthorized });
                }
                // Default to 400 for other auth service related login errors
                return BadRequest(new ProblemDetails { Title = "Login Error", Detail = ex.Message, Status = StatusCodes.Status400BadRequest });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during login for {UsernameOrEmail}", loginRequest.UsernameOrEmail);
                return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Login Error", Detail = "An unexpected error occurred." });
            }
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)] // Updated DTO
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)] // For invalid refresh token
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var userAgent = Request.Headers["User-Agent"].ToString() ?? "unknown";

            try
            {
                var tokenResponse = await _authService.RefreshTokenAsync(request, ipAddress, userAgent);
                return Ok(tokenResponse);
            }
            catch (AuthServiceException ex)
            {
                _logger.LogWarning(ex, "Token refresh failed: {Message}", ex.Message);
                if (ex.Message.Contains("Invalid refresh token", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("Account is blocked", StringComparison.OrdinalIgnoreCase))
                {
                     return Unauthorized(new ProblemDetails { Title = "Token Refresh Failed", Detail = ex.Message, Status = StatusCodes.Status401Unauthorized });
                }
                return BadRequest(new ProblemDetails { Title = "Token Refresh Error", Detail = ex.Message, Status = StatusCodes.Status400BadRequest });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during token refresh.");
                return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Token Refresh Error", Detail = "An unexpected error occurred." });
            }
        }

        [AllowAnonymous]
        [HttpPost("request-password-reset")]
        [ProducesResponseType(typeof(PasswordResetResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For validation
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)] // For rate limiting
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                var responseDto = await _authService.RequestPasswordResetAsync(request);
                // The service handles rate limiting internally and should return a DTO with appropriate message.
                return Ok(responseDto);
            }
            catch (AuthServiceException ex)
            {
                _logger.LogWarning(ex, "Request password reset failed for email {Email}: {Message}", request.Email, ex.Message);
                if (ex.Message.Contains("Rate limit hit", StringComparison.OrdinalIgnoreCase))
                {
                    // The DTO from service might already have a user-friendly message for rate limiting.
                    // If the exception is specifically for rate limiting, use 429.
                    return StatusCode(StatusCodes.Status429TooManyRequests, new ProblemDetails { Title = "Password Reset Request Limit", Detail = ex.Message, Status = StatusCodes.Status429TooManyRequests });
                }
                 // For other errors like "User not found", service might throw.
                if (ex.Message.Contains("not found", StringComparison.OrdinalIgnoreCase)) {
                    // Still return OK with generic message to prevent email enumeration, as per original logic for RequestPasswordReset.
                    // The DTO itself from the service should handle this. If service throws, it's an actual error.
                    // For now, if service throws, treat as a server-side issue or bad request if message indicates.
                     return BadRequest(new ProblemDetails { Title = "Password Reset Request Error", Detail = ex.Message, Status = StatusCodes.Status400BadRequest });
                }
                return BadRequest(new ProblemDetails { Title = "Password Reset Request Error", Detail = ex.Message, Status = StatusCodes.Status400BadRequest });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during password reset request for email {Email}", request.Email);
                return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Password Reset Request Error", Detail = "An unexpected error occurred." });
            }
        }

        [AllowAnonymous]
        [HttpPost("restore-password")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)] // Returns { success: bool, message: string } - consider changing to a specific DTO
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For invalid token/session or validation
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> RestorePassword([FromBody] PasswordRestoreRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                await _authService.RestorePasswordAsync(request);
                // If successful, the service doesn't throw. The message is generic.
                return Ok(new { Success = true, Message = "Password has been successfully restored." });
            }
            catch (AuthServiceException ex)
            {
                _logger.LogWarning(ex, "Password restore failed for session {SessionId}: {Message}", request.SessionId, ex.Message);
                // Based on original logic: "Invalid or expired", "already been used", "has expired"
                if (ex.Message.Contains("Invalid or expired", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("already been used", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("has expired", StringComparison.OrdinalIgnoreCase))
                {
                    return BadRequest(new ProblemDetails { Title = "Password Restore Failed", Detail = ex.Message, Status = StatusCodes.Status400BadRequest });
                }
                return BadRequest(new ProblemDetails { Title = "Password Restore Failed", Detail = ex.Message, Status = StatusCodes.Status400BadRequest });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during password restore for session {SessionId}", request.SessionId);
                return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Password Restore Error", Detail = "An unexpected error occurred." });
            }
        }

        [AllowAnonymous]
        [HttpPost("confirm-email")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)] // Returns { message: string }
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For invalid/expired token
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> ConfirmEmail([FromBody] EmailConfirmationRequestDto request)
        {
            if (!ModelState.IsValid || string.IsNullOrEmpty(request.Token))
            {
                return BadRequest(new ProblemDetails { Title = "Email Confirmation Failed", Detail = "Token is required.", Status = StatusCodes.Status400BadRequest });
            }
            
            try
            {
                await _authService.ConfirmEmailAsync(request.Token);
                return Ok(new { Message = "Email confirmed successfully." });
            }
            catch (AuthServiceException ex)
            {
                _logger.LogWarning(ex, "Email confirmation failed for token {Token}: {Message}", request.Token, ex.Message);
                // Based on original logic: "Invalid or already used", "has expired", "System configuration error"
                if (ex.Message.Contains("Invalid or already used", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("has expired", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("System configuration error", StringComparison.OrdinalIgnoreCase))
                {
                     return BadRequest(new ProblemDetails { Title = "Email Confirmation Failed", Detail = ex.Message, Status = StatusCodes.Status400BadRequest });
                }
                return BadRequest(new ProblemDetails { Title = "Email Confirmation Failed", Detail = ex.Message, Status = StatusCodes.Status400BadRequest });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during email confirmation for token {Token}", request.Token);
                return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Email Confirmation Error", Detail = "An unexpected error occurred." });
            }
        }

        [AllowAnonymous]
        [HttpPost("resend-confirmation")]
        // Consider a specific DTO for response if `ResendConfirmationResponseDto` is not suitable or if service changes.
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)] // Example: { Success = true, Message = "..." }
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                await _authService.ResendConfirmationEmailAsync(request);
                return Ok(new { Success = true, Message = "If your email address is registered and unconfirmed, a new confirmation email has been sent." });
            }
            catch (AuthServiceException ex)
            {
                _logger.LogWarning(ex, "Resend confirmation email failed for {Email}: {Message}", request.Email, ex.Message);
                var problemDetails = new ProblemDetails { Title = "Resend Confirmation Failed", Detail = ex.Message };
                
                if (ex.Message.Contains("already been confirmed", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("recently sent", StringComparison.OrdinalIgnoreCase))
                {
                    problemDetails.Status = StatusCodes.Status400BadRequest;
                    return BadRequest(problemDetails);
                }
                // Check for rate limit messages if service throws them
                if (ex.Message.Contains("Rate limit", StringComparison.OrdinalIgnoreCase)) // Generic check
                {
                    problemDetails.Status = StatusCodes.Status429TooManyRequests;
                    return StatusCode(StatusCodes.Status429TooManyRequests, problemDetails);
                }
                // Default for other AuthServiceExceptions during resend
                problemDetails.Status = StatusCodes.Status400BadRequest;
                return BadRequest(problemDetails);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during resend confirmation email for {Email}", request.Email);
                return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Resend Confirmation Error", Detail = "An unexpected error occurred." });
            }
        }

        // [Authorize] attribute restricts access to this endpoint to authenticated users only.
        // If a user is not authenticated, they will typically receive a 401 Unauthorized response.
        [Authorize] // Requires authentication
        [HttpGet("profile")]
        [ProducesResponseType(typeof(ProfileResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> GetProfile()
        // Uses the helper method to get the current user's ID from their authentication token.
        {
            // Uses the helper method to get the current user's ID from their authentication token.
            var userId = GetCurrentUserId(); // Helper to get ID from token claims
            var (success, profile, message) = await _userService.GetUserProfileAsync(userId);

            if (success && profile != null)
            {
                return Ok(profile);
            }
            
            if (message.Contains("not found", StringComparison.OrdinalIgnoreCase))
            {
                return NotFound(new ProblemDetails { Title = "Profile Not Found", Detail = message, Status = StatusCodes.Status404NotFound });
            }

            _logger.LogError("Failed to get profile for user {UserId}: {Message}", userId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Get Profile Error", Detail = message });
        }

        [Authorize] // Requires authentication
        [HttpPut("profile")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For validation or username taken
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequestDto profileRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userId = GetCurrentUserId();
            var (success, message) = await _userService.UpdateUserProfileAsync(userId, profileRequest);

            if (success)
            {
                return Ok(new { Message = message }); // Message could be "Profile updated" or "No changes"
            }

            if (message.Contains("not found", StringComparison.OrdinalIgnoreCase))
            {
                return NotFound(new ProblemDetails { Title = "Update Profile Failed", Detail = message, Status = StatusCodes.Status404NotFound });
            }
            if (message.Contains("already taken", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("already in use", StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest(new ProblemDetails { Title = "Update Profile Failed", Detail = message, Status = StatusCodes.Status400BadRequest });
            }
            
            _logger.LogError("Failed to update profile for user {UserId}: {Message}", userId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Update Profile Error", Detail = message });
        }

        // --- User Profile Image Endpoints ---

        [Authorize]
        [HttpGet("profile/image")]
        [ProducesResponseType(typeof(FileContentResult), StatusCodes.Status200OK)] // Returns image directly
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> GetProfileImage()
        {
            // This endpoint serves a file (the user's profile image) directly.
            var userId = GetCurrentUserId();
            var (success, imageDto, message) = await _userService.GetUserProfileImageAsync(userId);

            if (success && imageDto != null)
            {
                return File(imageDto.ImageData, imageDto.MimeType);
            }

            if (message.Contains("not found", StringComparison.OrdinalIgnoreCase))
            {
                return NotFound(new ProblemDetails { Title = "Profile Image Not Found", Detail = message, Status = StatusCodes.Status404NotFound });
            }

            _logger.LogError("Failed to get profile image for user {UserId}: {Message}", userId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Get Profile Image Error", Detail = message });
        }

        [Authorize]
        [HttpPost("profile/image")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)] // Returns { message: string }
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For validation, file type/size errors
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)] // User not found
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> UploadProfileImage([FromForm] UploadProfileImageRequestDto request) // Use FromForm for IFormFile
        // [FromForm] attribute is used to bind data from a submitted form, typically multipart/form-data, which is used for file uploads.
        {
            if (request.ImageFile == null || request.ImageFile.Length == 0)
            {
                return BadRequest(new ProblemDetails { Title = "Upload Profile Image Failed", Detail = "No image file provided.", Status = StatusCodes.Status400BadRequest });
            }

            var userId = GetCurrentUserId();
            var (success, message) = await _userService.UploadUserProfileImageAsync(userId, request.ImageFile);

            if (success)
            {
                return Ok(new { Message = message });
            }

            if (message.Contains("not found", StringComparison.OrdinalIgnoreCase)) // User not found
            {
                return NotFound(new ProblemDetails { Title = "Upload Profile Image Failed", Detail = message, Status = StatusCodes.Status404NotFound });
            }
            if (message.Contains("Invalid file type", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("exceeds the limit", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("No image file provided", StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest(new ProblemDetails { Title = "Upload Profile Image Failed", Detail = message, Status = StatusCodes.Status400BadRequest });
            }

            _logger.LogError("Failed to upload profile image for user {UserId}: {Message}", userId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Upload Profile Image Error", Detail = message });
        }

        [Authorize]
        [HttpDelete("profile/image")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)] // Returns { message: string }
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)] // Image not found
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> DeleteProfileImage()
        {
            var userId = GetCurrentUserId();
            var (success, message) = await _userService.DeleteUserProfileImageAsync(userId);

            if (success)
            {
                return Ok(new { Message = message });
            }

            if (message.Contains("not found", StringComparison.OrdinalIgnoreCase))
            {
                return NotFound(new ProblemDetails { Title = "Delete Profile Image Failed", Detail = message, Status = StatusCodes.Status404NotFound });
            }

            _logger.LogError("Failed to delete profile image for user {UserId}: {Message}", userId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Delete Profile Image Error", Detail = message });
        }

        // --- User Settings Endpoints ---

        [Authorize]
        [HttpGet("settings")]
        [ProducesResponseType(typeof(UserSettingsDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)] // User not found (if settings auto-creation fails)
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> GetUserSettings()
        {
            var userId = GetCurrentUserId();
            var (success, settingsDto, message) = await _userService.GetUserSettingsAsync(userId);

            if (success && settingsDto != null)
            {
                return Ok(settingsDto);
            }
            
            // GetUserSettingsAsync in service attempts to create default settings if not found.
            // So a "not found" here would imply the user themselves wasn't found during that process.
            if (message.Contains("User not found", StringComparison.OrdinalIgnoreCase))
            {
                 return NotFound(new ProblemDetails { Title = "Get User Settings Failed", Detail = message, Status = StatusCodes.Status404NotFound });
            }

            _logger.LogError("Failed to get settings for user {UserId}: {Message}", userId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Get User Settings Error", Detail = message });
        }

        [Authorize]
        [HttpPut("settings")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)] // Returns { message: string }
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For validation errors
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)] // User not found
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> UpdateUserSettings([FromBody] UpdateUserSettingsRequestDto settingsRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userId = GetCurrentUserId();
            var (success, message) = await _userService.UpdateUserSettingsAsync(userId, settingsRequest);

            if (success)
            {
                return Ok(new { Message = message });
            }

            if (message.Contains("User not found", StringComparison.OrdinalIgnoreCase))
            {
                 return NotFound(new ProblemDetails { Title = "Update User Settings Failed", Detail = message, Status = StatusCodes.Status404NotFound });
            }

            _logger.LogError("Failed to update settings for user {UserId}: {Message}", userId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Update User Settings Error", Detail = message });
        }


        [Authorize]
        [HttpPost("follow")]
        [ProducesResponseType(typeof(FollowResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // e.g. cannot follow self, user not found
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> SetFollowing([FromBody] FollowRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var followerId = GetCurrentUserId();
            var (success, message) = await _userService.SetFollowingAsync(followerId, request.FolloweeId, request.Follow);

            if (success)
            {
                return Ok(new FollowResponseDto { Success = true, Message = message });
            }

            // Check for specific error messages from service to return appropriate status codes
            if (message.Contains("Cannot follow yourself", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("User not found", StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest(new ProblemDetails { Title = "Follow Operation Failed", Detail = message, Status = StatusCodes.Status400BadRequest });
            }
            
            _logger.LogError("SetFollowing failed for follower {FollowerId} and followee {FolloweeId}: {Message}", followerId, request.FolloweeId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Follow Operation Error", Detail = message });
        }

        [Authorize]
        [HttpPost("change-password/initiate")]
        [ProducesResponseType(typeof(InitiatePasswordChangeResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For invalid current password or validation
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)] // If somehow user ID is not found but authorized
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> InitiatePasswordChange([FromBody] InitiatePasswordChangeRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userId = GetCurrentUserId();
            try
            {
                var responseDto = await _authService.InitiatePasswordChangeAsync(userId, request);
                return Ok(responseDto);
            }
            catch (AuthServiceException ex)
            {
                _logger.LogWarning(ex, "Initiate password change failed for user {UserId}: {Message}", userId, ex.Message);
                var problemDetails = new ProblemDetails { Title = "Password Change Initiation Failed", Detail = ex.Message };
                if (ex.Message.Contains("Invalid current password", StringComparison.OrdinalIgnoreCase))
                {
                    problemDetails.Status = StatusCodes.Status400BadRequest;
                    return BadRequest(problemDetails);
                }
                if (ex.Message.Contains("User not found", StringComparison.OrdinalIgnoreCase)) // Should be rare if authorized
                {
                    problemDetails.Status = StatusCodes.Status401Unauthorized;
                     return Unauthorized(problemDetails);
                }
                problemDetails.Status = StatusCodes.Status400BadRequest; // Default for other auth errors
                return BadRequest(problemDetails);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during password change initiation for user {UserId}", userId);
                return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Password Change Initiation Error", Detail = "An unexpected error occurred." });
            }
        }

        [Authorize]
        [HttpPost("change-password/complete")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)] // Returns { success: bool, message: string }
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For invalid code/ID or validation
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> CompletePasswordChange([FromBody] CompletePasswordChangeRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userId = GetCurrentUserId();
            try
            {
                await _authService.CompletePasswordChangeAsync(userId, request);
                return Ok(new { Success = true, Message = "Password changed successfully." });
            }
            catch (AuthServiceException ex)
            {
                _logger.LogWarning(ex, "Complete password change failed for user {UserId}: {Message}", userId, ex.Message);
                // Based on original logic: "Invalid or already used", "has expired", "User not found"
                var problemDetails = new ProblemDetails { Title = "Complete Password Change Failed", Detail = ex.Message };
                if (ex.Message.Contains("Invalid or already used", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("has expired", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("User not found", StringComparison.OrdinalIgnoreCase))
                {
                    problemDetails.Status = StatusCodes.Status400BadRequest;
                    return BadRequest(problemDetails);
                }
                problemDetails.Status = StatusCodes.Status400BadRequest; // Default
                return BadRequest(problemDetails);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during password change completion for user {UserId}", userId);
                return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Complete Password Change Error", Detail = "An unexpected error occurred." });
            }
        }

        [Authorize]
        [HttpPost("logout")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)] // Returns { message: string }
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> Logout()
        {
            var userId = GetCurrentUserId();
            var sidClaim = User.Claims.FirstOrDefault(c => c.Type == "sid")?.Value;
            Guid? sessionId = null;
            if (Guid.TryParse(sidClaim, out var parsedSid))
            {
                sessionId = parsedSid;
            }

            try
            {
                await _authService.LogoutAsync(userId, sessionId);
                return Ok("Logout successful");
            }
            catch (AuthServiceException ex)
            {
                _logger.LogWarning(ex, "Logout failed for user {UserId}, session {SessionId}: {Message}", userId, sessionId, ex.Message);
                // Most AuthServiceExceptions during logout might not be critical client-facing errors.
                // If the message indicates an "unexpected error" or similar, treat as 500.
                if (ex.Message.Contains("unexpected error", StringComparison.OrdinalIgnoreCase)) {
                     return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Logout Error", Detail = ex.Message, Status = StatusCodes.Status500InternalServerError });
                }
                // For other cases (e.g., session already invalidated), still return Ok.
                return Ok(new { Message = "Logout processed." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during logout for user {UserId}, session {SessionId}", userId, sessionId);
                return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Logout Error", Detail = "An unexpected error occurred during logout." });
            }
        }

    }
}

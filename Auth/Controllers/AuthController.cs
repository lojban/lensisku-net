// This 'using' directive imports namespaces, making types within them accessible without full qualification.
using Lensisku.Auth.DTOs;
using Lensisku.Auth.Services;
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
        private readonly IRoleService _roleService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IAuthService authService,
            // This constructor demonstrates Dependency Injection (DI).
            // ASP.NET Core's built-in DI container provides instances of IAuthService, IUserService, etc.
            // This promotes loose coupling and testability.
            IUserService userService,
            IRoleService roleService,
            ILogger<AuthController> logger)
        {
            _authService = authService;
            _userService = userService;
            _roleService = roleService;
            _logger = logger;
        }

        // Helper to get current user's ID from claims
        // Claims are pieces of information (e.g., user ID, roles, permissions) asserted about a subject (user),
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
            throw new InvalidOperationException("User ID not found in token claims.");
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
        [ProducesResponseType(typeof(TokenResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)] // For username/email exists
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For validation errors
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        // 'async Task<IActionResult>' indicates an asynchronous action method that returns a generic action result.
        // IActionResult allows returning various HTTP responses (Ok, BadRequest, NotFound, etc.).
        // 'async Task<IActionResult>' indicates an asynchronous action method that returns a generic action result.
        // IActionResult allows returning various HTTP responses (Ok, BadRequest, NotFound, etc.).
        public async Task<IActionResult> Signup([FromBody] SignupRequestDto signupRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Calls the authentication service to handle the signup logic.
            // This separation of concerns (controller for HTTP, service for business logic) is a key design principle.
            // Calls the authentication service to handle the signup logic.
            // This separation of concerns (controller for HTTP, service for business logic) is a key design principle.
            var (success, tokenResponse, message) = await _authService.SignupAsync(signupRequest);

            if (success && tokenResponse != null)
            {
                // Rust implementation controller returns a message and token.
                // Let's return the token response directly, message can be part of a custom ProblemDetails or just logged.
                return Ok(new { Message = message, Tokens = tokenResponse });
            }
            
            if (message.Contains("already exists", StringComparison.OrdinalIgnoreCase))
            {
                // Returns a 409 Conflict status if the username/email already exists.
                // Returns a 409 Conflict status if the username/email already exists.
                return Conflict(new ProblemDetails { Title = "Signup Failed", Detail = message, Status = StatusCodes.Status409Conflict });
            }

            _logger.LogError("Signup failed for user {Username}: {Message}", signupRequest.Username, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Signup Error", Detail = message });
        }

        [AllowAnonymous]
        [HttpPost("login")]
        [ProducesResponseType(typeof(TokenResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginRequest)
        // [FromBody] attribute tells ASP.NET Core to bind the request body (typically JSON) to the LoginRequestDto parameter.
        // [FromBody] attribute tells ASP.NET Core to bind the request body (typically JSON) to the LoginRequestDto parameter.

        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Get IP and UserAgent for session logging
            // HttpContext provides access to request and response details.
            // HttpContext provides access to request and response details.
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var userAgent = Request.Headers["User-Agent"].ToString() ?? "unknown";

            var (success, tokenResponse, message) = await _authService.LoginAsync(loginRequest, ipAddress, userAgent);

            if (success && tokenResponse != null)
            {
                return Ok(tokenResponse);
            }
            
            if (message.Contains("Invalid credentials", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("Account is blocked", StringComparison.OrdinalIgnoreCase))
            {
                // Returns a 401 Unauthorized status for failed login attempts.
                 return Unauthorized(new ProblemDetails { Title = "Login Failed", Detail = message, Status = StatusCodes.Status401Unauthorized });
                // Returns a 401 Unauthorized status for failed login attempts.
            }
            
            _logger.LogError("Login failed for {UsernameOrEmail}: {Message}", loginRequest.UsernameOrEmail, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Login Error", Detail = message });
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        [ProducesResponseType(typeof(TokenResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)] // For invalid refresh token
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var userAgent = Request.Headers["User-Agent"].ToString() ?? "unknown";

            var (success, tokenResponse, message) = await _authService.RefreshTokensAsync(request.RefreshToken, ipAddress, userAgent);

            if (success && tokenResponse != null)
            {
                // Returns a 200 OK status with the token response if login is successful.
                // Returns a 200 OK status with the token response if login is successful.
                return Ok(tokenResponse);
            }

            if (message.Contains("Invalid refresh token", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("Account is blocked", StringComparison.OrdinalIgnoreCase)) // Refresh might also fail if user is blocked
            {
                return Unauthorized(new ProblemDetails { Title = "Token Refresh Failed", Detail = message, Status = StatusCodes.Status401Unauthorized });
            }
            
            _logger.LogError("Token refresh failed: {Message}", message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Token Refresh Error", Detail = message });
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

            var (success, responseDto, message) = await _authService.RequestPasswordResetAsync(request);

            if (success && responseDto != null)
            {
                // The service method already returns a generic success message to prevent email enumeration.
                // If rate limited, the service returns success=true but a specific message.
                if (message.Contains("Rate limit hit", StringComparison.OrdinalIgnoreCase))
                {
                    // Although service returns success true, controller should indicate rate limit.
                    // However, to prevent info leak, we might just return OK with the generic message.
                    // For now, let's trust the service's DTO. If DTO's Success is true, it's OK.
                    // The message in DTO will be generic.
                    return Ok(responseDto);
                }
                return Ok(responseDto);
            }
            
            // If success is false, it's likely an internal server error from the service.
            _logger.LogError("Request password reset failed for email {Email}: {Message}", request.Email, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Password Reset Request Error", Detail = message });
        }

        [AllowAnonymous]
        [HttpPost("restore-password")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)] // Returns { success: bool, message: string }
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For invalid token/session or validation
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> RestorePassword([FromBody] PasswordRestoreRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var (success, message) = await _authService.RestorePasswordAsync(request);

            if (success)
            {
                return Ok(new { Success = true, Message = message });
            }
            
            if (message.Contains("Invalid or expired", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("already been used", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("has expired", StringComparison.OrdinalIgnoreCase))
            {
                 return BadRequest(new ProblemDetails { Title = "Password Restore Failed", Detail = message, Status = StatusCodes.Status400BadRequest });
            }

            _logger.LogError("Password restore failed for session {SessionId}: {Message}", request.SessionId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Password Restore Error", Detail = message });
        }

        [AllowAnonymous]
        [HttpPost("confirm-email")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)] // Returns { message: string }
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For invalid/expired token
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> ConfirmEmail([FromBody] EmailConfirmationRequestDto request) // Changed from web::Query in Rust
        // This endpoint handles email confirmation, a common feature for verifying user email addresses.
        // This endpoint handles email confirmation, a common feature for verifying user email addresses.
        {
            if (!ModelState.IsValid) // Token is required
            {
                return BadRequest(ModelState);
            }
            
            var (success, message) = await _authService.ConfirmEmailAsync(request.Token);

            if (success)
            {
                return Ok(new { Message = message });
            }

            if (message.Contains("Invalid or already used", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("has expired", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("System configuration error", StringComparison.OrdinalIgnoreCase)) // For missing Editor role
            {
                return BadRequest(new ProblemDetails { Title = "Email Confirmation Failed", Detail = message, Status = StatusCodes.Status400BadRequest });
            }
            
            _logger.LogError("Email confirmation failed for token {Token}: {Message}", request.Token, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Email Confirmation Error", Detail = message });
        }

        [AllowAnonymous]
        [HttpPost("resend-confirmation")]
        [ProducesResponseType(typeof(ResendConfirmationResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For already confirmed or other validation
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)] // For rate limiting (though service handles this with generic msg)
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var (success, message) = await _authService.ResendConfirmationEmailAsync(request);
            
            // The service returns a generic success message to prevent email enumeration if email not found.
            // If email is already confirmed, it returns success=false and specific message.
            // If rate limited by simple time check, it returns success=false and specific message.
            if (success)
            {
                return Ok(new ResendConfirmationResponseDto { Success = true, Message = message });
            }
            else // success == false
            {
                if (message.Contains("already been confirmed", StringComparison.OrdinalIgnoreCase) ||
                    message.Contains("recently sent", StringComparison.OrdinalIgnoreCase))
                {
                    // These are considered client errors (bad request) rather than server errors.
                    return BadRequest(new ProblemDetails { Title = "Resend Confirmation Failed", Detail = message, Status = StatusCodes.Status400BadRequest });
                }
                // For other errors from the service (which should be rare if it's just "unexpected error")
                _logger.LogError("Resend confirmation email failed for {Email}: {Message}", request.Email, message);
                return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Resend Confirmation Error", Detail = message });
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
            var (success, responseDto, message) = await _authService.InitiatePasswordChangeAsync(userId, request);

            if (success && responseDto != null)
            {
                return Ok(responseDto);
            }

            if (message.Contains("Invalid current password", StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest(new ProblemDetails { Title = "Password Change Initiation Failed", Detail = message, Status = StatusCodes.Status400BadRequest });
            }
            if (message.Contains("User not found", StringComparison.OrdinalIgnoreCase)) // Should be rare if authorized
            {
                 return Unauthorized(new ProblemDetails { Title = "Password Change Initiation Failed", Detail = message, Status = StatusCodes.Status401Unauthorized });
            }
            
            _logger.LogError("Initiate password change failed for user {UserId}: {Message}", userId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Password Change Initiation Error", Detail = message });
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
            var (success, message) = await _authService.CompletePasswordChangeAsync(userId, request);

            if (success)
            {
                return Ok(new { Success = true, Message = message });
            }

            if (message.Contains("Invalid or already used", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("has expired", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("User not found", StringComparison.OrdinalIgnoreCase)) // User not found should be rare here
            {
                return BadRequest(new ProblemDetails { Title = "Complete Password Change Failed", Detail = message, Status = StatusCodes.Status400BadRequest });
            }
            
            _logger.LogError("Complete password change failed for user {UserId}: {Message}", userId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Complete Password Change Error", Detail = message });
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

            var (success, message) = await _authService.LogoutAsync(userId, sessionId);

            if (success)
            {
                return Ok(new { Message = message });
            }
            
            _logger.LogError("Logout failed for user {UserId}, session {SessionId}: {Message}", userId, sessionId, message);
            // Even if service returns false (e.g. session not found to end), it's generally not a client error for logout.
            // But if it's an unexpected error, return 500.
            if (message.Contains("unexpected error", StringComparison.OrdinalIgnoreCase)) {
                 return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Logout Error", Detail = message });
            }
            // For "session not found" type messages from service, client can still consider logout successful.
            return Ok(new { Message = message }); // Or a more generic "Logout processed."
        }

        // --- Role and Permission Management Endpoints ---
        // These would typically require specific admin/management permissions.
        // Example: [Authorize(Roles = "Admin")] or [Authorize(Policy = "ManageRoles")]

        // Defines a constant for a policy name. Policies are a flexible way to define authorization requirements.
        // This policy ("ManageRoles") is likely configured in Program.cs to require specific claims or roles.
        public const string ManageRolesPolicy = "ManageRoles"; // Define policy name

        // This endpoint allows users with the "ManageRoles" policy to retrieve a list of permissions.
        [Authorize(Policy = ManageRolesPolicy)]
        [HttpGet("permissions")]
        [ProducesResponseType(typeof(PermissionsListResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> GetPermissions()
        {
            var permissions = await _roleService.ListPermissionsAsync();
            return Ok(new PermissionsListResponseDto { Permissions = permissions });
        }
        
        // This endpoint allows users with the "ManageRoles" policy to retrieve a list of roles.
        [Authorize(Policy = ManageRolesPolicy)]
        [HttpGet("roles")]
        [ProducesResponseType(typeof(UserRolesResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> GetRoles()
        {
            var actorRoleName = GetCurrentUserRoleName(); // Get role of the admin making the request
            var roles = await _roleService.GetRolesWithPermissionsAsync(actorRoleName);
            return Ok(new UserRolesResponseDto { Roles = roles });
        }

        [Authorize(Policy = ManageRolesPolicy)]
        [HttpPost("roles")]
        [ProducesResponseType(typeof(RoleResponseDto), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequestDto request)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var actorRoleName = GetCurrentUserRoleName();
            var (success, roleDto, message) = await _roleService.CreateRoleAsync(request, actorRoleName);

            if (success && roleDto != null)
            {
                // Returns a 201 Created status, indicating a new resource was created.
                // Returns a 201 Created status, indicating a new resource was created.
                return CreatedAtAction(nameof(GetRoles), new { /* route params if any for getting a specific role */ }, roleDto);
            }
            if (message.Contains("already exists", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("not found", StringComparison.OrdinalIgnoreCase) || // e.g. permission not found
                message.Contains("Cannot assign permission", StringComparison.OrdinalIgnoreCase))
            {
                 return BadRequest(new ProblemDetails { Title = "Create Role Failed", Detail = message, Status = StatusCodes.Status400BadRequest });
            }
            _logger.LogError("CreateRole failed: {Message}", message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Create Role Error", Detail = message });
        }

        [Authorize(Policy = ManageRolesPolicy)]
        // The "{roleName}" in the route template is a route parameter, captured as the 'roleName' string argument.
        // The "{roleName}" in the route template is a route parameter, captured as the 'roleName' string argument.
        [HttpPut("roles/{roleName}")]
        [ProducesResponseType(typeof(RoleResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> UpdateRole(string roleName, [FromBody] UpdateRoleRequestDto request)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var actorRoleName = GetCurrentUserRoleName();
            var (success, roleDto, message) = await _roleService.UpdateRoleAsync(roleName, request, actorRoleName);

            if (success && roleDto != null)
            {
                return Ok(roleDto);
            }
            if (message.Contains("not found", StringComparison.OrdinalIgnoreCase))
            {
                return NotFound(new ProblemDetails { Title = "Update Role Failed", Detail = message, Status = StatusCodes.Status404NotFound });
            }
            if (message.Contains("Cannot assign permission", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("cannot be directly updated", StringComparison.OrdinalIgnoreCase))
            {
                 return BadRequest(new ProblemDetails { Title = "Update Role Failed", Detail = message, Status = StatusCodes.Status400BadRequest });
            }
            _logger.LogError("UpdateRole for {RoleName} failed: {Message}", roleName, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Update Role Error", Detail = message });
        }

        [Authorize(Policy = ManageRolesPolicy)]
        [HttpDelete("roles/{roleName}")]
        [ProducesResponseType(StatusCodes.Status200OK)] // Returns { message: string }
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)] // For protected roles or other client errors
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> DeleteRole(string roleName)
        {
            var (success, message) = await _roleService.DeleteRoleAsync(roleName);
            if (success)
            {
                return Ok(new { Message = message });
            }
            if (message.Contains("not found", StringComparison.OrdinalIgnoreCase))
            {
                 return NotFound(new ProblemDetails { Title = "Delete Role Failed", Detail = message, Status = StatusCodes.Status404NotFound });
            }
            if (message.Contains("cannot be deleted", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("System configuration error", StringComparison.OrdinalIgnoreCase))
            {
                 return BadRequest(new ProblemDetails { Title = "Delete Role Failed", Detail = message, Status = StatusCodes.Status400BadRequest });
            }
            _logger.LogError("DeleteRole for {RoleName} failed: {Message}", roleName, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Delete Role Error", Detail = message });
        }

        [Authorize(Policy = ManageRolesPolicy)] // Or a more specific "AssignRoles" policy
        [HttpPost("assign-role")]
        [ProducesResponseType(typeof(AssignRoleResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden)] // If assigner lacks permission
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)] // User/role not found
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> AssignRole([FromBody] AssignRoleRequestDto request)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var assignerUserId = GetCurrentUserId();
            var (success, message) = await _roleService.AssignRoleAsync(assignerUserId, request.UserId, request.Role);
            
            if (success)
            {
                return Ok(new AssignRoleResponseDto { Success = true, Message = message });
            }

            if (message.Contains("not found", StringComparison.OrdinalIgnoreCase))
            {
                return NotFound(new ProblemDetails { Title = "Assign Role Failed", Detail = message, Status = StatusCodes.Status404NotFound });
            }
            if (message.Contains("does not have permission", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("cannot assign role", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("Only an Admin can assign", StringComparison.OrdinalIgnoreCase))
            {
                return Forbid(); // Or BadRequest depending on how strictly we map "permission denied" vs "bad input"
            }
             _logger.LogError("AssignRole for target {TargetUserId} to role {RoleName} by {AssignerId} failed: {Message}", request.UserId, request.Role, assignerUserId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Assign Role Error", Detail = message });
        }

        // block_user in Rust controller uses claims.sub for actor_id
        // Requires "block_users" permission (implicitly, or via policy)
        public const string BlockUsersPolicy = "BlockUsers"; // Define policy name
        // This policy likely requires the "block_users" permission claim.
        // This policy likely requires the "block_users" permission claim.

        [Authorize(Policy = BlockUsersPolicy)]
        [HttpPost("block-user")]
        [ProducesResponseType(typeof(BlockUserResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> BlockUser([FromBody] BlockUserRequestDto request)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var actorUserId = GetCurrentUserId();
            var (success, message) = await _roleService.BlockUserAsync(actorUserId, request.UserId, request.Block);

            if (success)
            {
                return Ok(new BlockUserResponseDto { Success = true, Message = message });
            }
            
            if (message.Contains("not found", StringComparison.OrdinalIgnoreCase))
            {
                return NotFound(new ProblemDetails { Title = "Block User Failed", Detail = message, Status = StatusCodes.Status404NotFound });
            }
            if (message.Contains("does not have permission", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("Cannot block", StringComparison.OrdinalIgnoreCase)) // Catches "Cannot block an Admin" or "Cannot block yourself"
            {
                 return Forbid(); // Or BadRequest
            }
            _logger.LogError("BlockUser for target {TargetUserId} by {ActorId} failed: {Message}", request.UserId, actorUserId, message);
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails { Title = "Block User Error", Detail = message });
        }
    }
}

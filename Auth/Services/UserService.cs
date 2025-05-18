using Lensisku.Auth.DTOs;
using Lensisku.Auth.Models; // Required for User model if not using DTOs internally for some ops
using Lensisku.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.IO; // For MemoryStream
using System.Linq; // For Select
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http; // For IFormFile

namespace Lensisku.Auth.Services
{
    // UserService implements IUserService and contains business logic related to user profiles,
    // following functionality, profile images, and user settings.
    public class UserService : IUserService
    {
        private readonly AppDbContext _context;
        private readonly ILogger<UserService> _logger;

        // Constructor for dependency injection.
        public UserService(AppDbContext context, ILogger<UserService> logger)
        {
            _context = context;
            _logger = logger;
        }

        // Retrieves a user's profile information.
        public async Task<(bool Success, ProfileResponseDto? Profile, string Message)> GetUserProfileAsync(int userId)
        {
            try
            {
                // Queries the Users table for a user with the given userId.
                var userEntity = await _context.Users
                    .Where(u => u.UserId == userId)
                    .FirstOrDefaultAsync();

                if (userEntity == null)
                {
                    return (false, null, "User profile not found.");
                }

                // ProfileResponseDto has RealName, Url, Personal. User.cs does not.
                // These will be null or default in the DTO.
                // If these fields were intended to be sourced from UserSettings or elsewhere, that logic would go here.
                var profileDto = new ProfileResponseDto
                {
                    // RealName, Url, Personal are not directly on User.cs
                    // If they were on UserSettings, it would be something like:
                    // RealName = userEntity.Settings?.RealName, // Assuming UserSettings has RealName
                    // For now, they will remain null as per ProfileResponseDto's definition and User.cs's lack of these fields.
                    RealName = null, // Explicitly null as User.cs doesn't have a direct match
                    Url = null,      // Explicitly null
                    Personal = null  // Explicitly null
                };
                
                // If ProfileResponseDto were to include Username, Email etc., you'd map them:
                // profileDto.Username = userEntity.Username;
                // profileDto.Email = userEntity.Email;

                return (true, profileDto, "Profile retrieved successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving profile for user {UserId}", userId);
                return (false, null, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Updates a user's profile information.
        public async Task<(bool Success, string Message)> UpdateUserProfileAsync(int userId, UpdateProfileRequestDto profileRequest)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return (false, "User not found.");
                }

                bool changed = false;
                if (profileRequest.Username != null && user.Username != profileRequest.Username)
                {
                    // If username is being changed, check for uniqueness.
                    if (await _context.Users.AnyAsync(u => u.Username == profileRequest.Username && u.UserId != userId))
                    {
                        return (false, "Username already taken.");
                    }
                    user.Username = profileRequest.Username;
                    changed = true;
                }

                // UpdateProfileRequestDto has RealName, Url, Personal.
                // User.cs does not have these fields directly.
                // If these were to be updated on UserSettings, that logic would be here.
                // For now, as User.cs doesn't have them, we cannot update them on the User object.
                // The following lines are commented out as User.cs does not have these properties.
                // if (profileRequest.RealName != null /* && user.RealName != profileRequest.RealName */ ) { /* user.RealName = profileRequest.RealName; changed = true; */ }
                // if (profileRequest.Url != null /* && user.Url != profileRequest.Url */ ) { /* user.Url = profileRequest.Url; changed = true; */ }
                // if (profileRequest.Personal != null /* && user.Personal != profileRequest.Personal */ ) { /* user.Personal = profileRequest.Personal; changed = true; */ }


                if (changed)
                {
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Profile updated for user {UserId}", userId);
                    return (true, "Profile updated successfully.");
                }
                
                return (true, "No changes detected in profile.");
            }
            // Catches exceptions specific to database update operations (e.g., constraint violations).
            catch (DbUpdateException ex) // Catch specific EF Core update exceptions
            {
                 _logger.LogError(ex, "Database error updating profile for user {UserId}", userId);
                 // Check for unique constraint violations if any (e.g. if email was part of profile update)
                 if (ex.InnerException?.Message.Contains("unique constraint") == true || ex.InnerException?.Message.Contains("duplicate key") == true)
                 {
                     return (false, "A value you tried to update is already in use (e.g., username).");
                 }
                 return (false, "A database error occurred while updating the profile.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating profile for user {UserId}", userId);
                return (false, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Allows a user (follower) to follow or unfollow another user (followee).
        public async Task<(bool Success, string Message)> SetFollowingAsync(int followerId, int followeeId, bool wantsToFollow)
        {
            // Prevents a user from following themselves.
            if (followerId == followeeId)
            {
                return (false, "Cannot follow yourself.");
            }

            try
            {
                // Fetching users separately to update their follower counts if necessary.
                var followerUser = await _context.Users.FindAsync(followerId);
                var followeeUser = await _context.Users.FindAsync(followeeId); // We need to update followeeUser.Followers

                if (followerUser == null) return (false, "Follower user not found.");
                if (followeeUser == null) return (false, "Followee user not found.");

                var existingFollow = await _context.Follows
                    // Checks if a follow relationship already exists.
                    .FirstOrDefaultAsync(f => f.FollowerId == followerId && f.FolloweeId == followeeId);

                if (wantsToFollow)
                {
                    if (existingFollow != null)
                    {
                        return (true, $"You are already following {followeeUser.Username}.");
                    }

                    var newFollow = new Follow
                    {
                        FollowerId = followerId,
                        FolloweeId = followeeId,
                        CreatedAt = DateTime.UtcNow
                    };
                    _context.Follows.Add(newFollow);
                    
                    // Denormalized count: Updates the 'Followers' count directly on the User entity.
                    // Update denormalized followers count on the followeeUser
                    followeeUser.Followers++;
                    
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("User {FollowerId} started following user {FolloweeId}", followerId, followeeId);
                    return (true, $"Successfully started following {followeeUser.Username}.");
                }
                else // wantsToUnfollow
                {
                    if (existingFollow == null)
                    {
                        return (true, $"You are not currently following {followeeUser.Username}.");
                    }

                    _context.Follows.Remove(existingFollow);

                    // Denormalized count: Decrements the 'Followers' count.
                    // Update denormalized followers count
                    if (followeeUser.Followers > 0)
                    {
                        followeeUser.Followers--;
                    }
                    
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("User {FollowerId} unfollowed user {FolloweeId}", followerId, followeeId);
                    return (true, $"Successfully unfollowed {followeeUser.Username}.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting follow status for follower {FollowerId} and followee {FolloweeId}", followerId, followeeId);
                return (false, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Profile Image Methods
        // Retrieves the profile image for a user.
        public async Task<(bool Success, UserProfileImageDto? Image, string Message)> GetUserProfileImageAsync(int userId)
        {
            try
            {
                var image = await _context.UserProfileImages
                    .Where(upi => upi.UserId == userId)
                    .Select(upi => new UserProfileImageDto
                    {
                        UserId = upi.UserId,
                        ImageData = upi.ImageData,
                        MimeType = upi.MimeType,
                        UpdatedAt = upi.UpdatedAt
                    })
                    .FirstOrDefaultAsync();

                if (image == null)
                {
                    return (false, null, "Profile image not found.");
                }
                return (true, image, "Profile image retrieved successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving profile image for user {UserId}", userId);
                return (false, null, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Uploads or updates a user's profile image.
        public async Task<(bool Success, string Message)> UploadUserProfileImageAsync(int userId, IFormFile imageFile)
        {
            if (imageFile == null || imageFile.Length == 0)
            {
                return (false, "No image file provided or file is empty.");
            }

            // Basic validation for file type and size (can be expanded)
            // Ensures the uploaded file is an allowed image type and within size limits.
            var allowedMimeTypes = new[] { "image/jpeg", "image/png", "image/gif" };
            if (!allowedMimeTypes.Contains(imageFile.ContentType.ToLower()))
            {
                return (false, "Invalid file type. Only JPG, PNG, GIF are allowed.");
            }

            long maxFileSize = 5 * 1024 * 1024; // 5 MB
            if (imageFile.Length > maxFileSize)
            {
                return (false, $"File size exceeds the limit of {maxFileSize / (1024 * 1024)} MB.");
            }

            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return (false, "User not found.");
                }

                // Reads the image file into a byte array.
                using var memoryStream = new MemoryStream();
                await imageFile.CopyToAsync(memoryStream);
                var imageData = memoryStream.ToArray();

                var userProfileImage = await _context.UserProfileImages.FindAsync(userId);
                if (userProfileImage == null)
                {
                    userProfileImage = new UserProfileImage
                    {
                        UserId = userId,
                    };
                    _context.UserProfileImages.Add(userProfileImage);
                    // If no image exists, a new UserProfileImage record is created.
                }

                userProfileImage.ImageData = imageData;
                userProfileImage.MimeType = imageFile.ContentType;
                userProfileImage.UpdatedAt = DateTime.UtcNow;

                await _context.SaveChangesAsync();
                _logger.LogInformation("Profile image uploaded for user {UserId}", userId);
                return (true, "Profile image uploaded successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading profile image for user {UserId}", userId);
                return (false, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Deletes a user's profile image.
        public async Task<(bool Success, string Message)> DeleteUserProfileImageAsync(int userId)
        {
            try
            {
                var userProfileImage = await _context.UserProfileImages.FindAsync(userId);
                if (userProfileImage == null)
                {
                    return (false, "Profile image not found or already deleted.");
                }

                _context.UserProfileImages.Remove(userProfileImage);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Profile image deleted for user {UserId}", userId);
                return (true, "Profile image deleted successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting profile image for user {UserId}", userId);
                return (false, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // User Settings Methods
        // Retrieves settings for a user.
        public async Task<(bool Success, UserSettingsDto? Settings, string Message)> GetUserSettingsAsync(int userId)
        {
            try
            {
                var settings = await _context.UserSettings
                    .Where(us => us.UserId == userId)
                    .Select(us => new UserSettingsDto
                    {
                        UserId = us.UserId,
                        OptimalRetention = us.OptimalRetention,
                        LastCalculated = us.LastCalculated
                    })
                    .FirstOrDefaultAsync();

                if (settings == null)
                {
                    // If settings don't exist, create default settings for the user.
                    // Optionally, create default settings if they don't exist
                    var user = await _context.Users.FindAsync(userId);
                    if (user == null) return (false, null, "User not found.");

                    var defaultSettings = new UserSettings { UserId = userId }; // Defaults are set in model
                    _context.UserSettings.Add(defaultSettings);
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Created default settings for user {UserId}", userId);
                    return (true, new UserSettingsDto { UserId = userId, OptimalRetention = defaultSettings.OptimalRetention, LastCalculated = defaultSettings.LastCalculated }, "Default settings created and retrieved.");
                }
                return (true, settings, "User settings retrieved successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving settings for user {UserId}", userId);
                return (false, null, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Updates user settings.
        public async Task<(bool Success, string Message)> UpdateUserSettingsAsync(int userId, UpdateUserSettingsRequestDto settingsRequest)
        {
            try
            {
                var userSettings = await _context.UserSettings.FindAsync(userId);
                if (userSettings == null)
                {
                     // If settings don't exist, create them before updating.
                     var user = await _context.Users.FindAsync(userId);
                    if (user == null) return (false, "User not found, cannot create settings.");
                    
                    userSettings = new UserSettings { UserId = userId };
                    _context.UserSettings.Add(userSettings);
                }

                userSettings.OptimalRetention = settingsRequest.OptimalRetention;
                userSettings.LastCalculated = DateTime.UtcNow; // Update last calculated time on change

                await _context.SaveChangesAsync();
                _logger.LogInformation("Settings updated for user {UserId}", userId);
                return (true, "User settings updated successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating settings for user {UserId}", userId);
                return (false, $"An unexpected error occurred: {ex.Message}");
            }
        }
    }
}

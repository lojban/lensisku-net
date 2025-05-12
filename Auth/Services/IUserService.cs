using Lensisku.Auth.DTOs;
using Microsoft.AspNetCore.Http; // For IFormFile
using System.Threading.Tasks;

namespace Lensisku.Auth.Services
{
    // IUserService defines the contract for user-related operations,
    // such as managing profiles, follow relationships, profile images, and user settings.
    public interface IUserService
    {
        // Retrieves a user's profile information.
        Task<(bool Success, ProfileResponseDto? Profile, string Message)> GetUserProfileAsync(int userId);
        // Updates a user's profile.
        Task<(bool Success, string Message)> UpdateUserProfileAsync(int userId, UpdateProfileRequestDto profileRequest);
        // Sets or unsets a follow relationship between two users.
        Task<(bool Success, string Message)> SetFollowingAsync(int followerId, int followeeId, bool wantsToFollow);

        // Profile Image
        // Retrieves a user's profile image.
        Task<(bool Success, UserProfileImageDto? Image, string Message)> GetUserProfileImageAsync(int userId);
        // Uploads or updates a user's profile image. Takes an IFormFile as input.
        Task<(bool Success, string Message)> UploadUserProfileImageAsync(int userId, IFormFile imageFile);
        // Deletes a user's profile image.
        Task<(bool Success, string Message)> DeleteUserProfileImageAsync(int userId);

        // User Settings
        // Retrieves a user's application settings.
        Task<(bool Success, UserSettingsDto? Settings, string Message)> GetUserSettingsAsync(int userId);
        // Updates a user's application settings.
        Task<(bool Success, string Message)> UpdateUserSettingsAsync(int userId, UpdateUserSettingsRequestDto settingsRequest);
        // BlockUser and AssignRole are more admin-level, might go into an AdminService or RoleService,
        // but Rust had block_user and assign_role in auth::service.
        // For now, let's assume they might be part of a more privileged service or IRoleService.
    }
}
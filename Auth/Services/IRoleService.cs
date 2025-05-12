using Lensisku.Auth.DTOs;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Lensisku.Auth.Services
{
    // IRoleService defines the contract for managing roles, permissions, and user assignments to roles.
    public interface IRoleService
    {
        // Lists all available permissions in the system.
        Task<List<PermissionInfoDto>> ListPermissionsAsync();
        // Gets a list of roles along with their assigned permissions, potentially filtered by the actor's role capabilities.
        Task<List<RoleWithPermissionsDto>> GetRolesWithPermissionsAsync(string actorRoleName); // actorRoleName to filter permissions

        // Creates a new role. The actorRoleName is used for permission checks.
        
        Task<(bool Success, RoleResponseDto? Role, string Message)> CreateRoleAsync(CreateRoleRequestDto request, string actorRoleName);
        // Updates an existing role (e.g., its permissions). ActorRoleName for permission checks.
        Task<(bool Success, RoleResponseDto? Role, string Message)> UpdateRoleAsync(string roleName, UpdateRoleRequestDto request, string actorRoleName);
        // Deletes a role.
        Task<(bool Success, string Message)> DeleteRoleAsync(string roleName); // actorRoleName/ID might be needed for permission check internally

        // Assigns a role to a user. Requires assigner's ID for permission checks.
        Task<(bool Success, string Message)> AssignRoleAsync(int assignerUserId, int targetUserId, string newRoleName);
        // Blocks or unblocks a user. Requires actor's ID for permission checks.
        Task<(bool Success, string Message)> BlockUserAsync(int actorUserId, int targetUserId, bool block);
    }
}
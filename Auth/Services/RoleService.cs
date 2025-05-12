using Lensisku.Auth.DTOs;
using Lensisku.Auth.Models;
using Lensisku.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Lensisku.Auth.Services
{
    // RoleService implements IRoleService and contains the business logic for managing roles and permissions.
    // It interacts with the database via AppDbContext.
    public class RoleService : IRoleService
    {
        // _context is an instance of AppDbContext, used for database operations.
        private readonly AppDbContext _context;
        // _logger is used for logging messages, warnings, and errors.
        private readonly ILogger<RoleService> _logger;

        // Constructor for dependency injection.
        public RoleService(AppDbContext context, ILogger<RoleService> logger)
        {
            _context = context;
            _logger = logger;
        }

        // Retrieves a list of all available permissions in the system.
        // 'async Task<List<PermissionInfoDto>>' indicates an asynchronous method returning a list of PermissionInfoDto.
        public async Task<List<PermissionInfoDto>> ListPermissionsAsync()
        {
            try
            {
                // Uses LINQ to query the Permissions table, order by name, and project into PermissionInfoDto.
                return await _context.Permissions
                    .OrderBy(p => p.Name)
                    .Select(p => new PermissionInfoDto { Name = p.Name, Description = p.Description })
                    .ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error listing permissions.");
                return new List<PermissionInfoDto>(); // Return empty list on error
            }
        }

        // Retrieves roles along with their permissions, filtered by what the 'actorRoleName' (the role of the user making the request)
        // is allowed to see or manage. This is important for hierarchical role management.
        public async Task<List<RoleWithPermissionsDto>> GetRolesWithPermissionsAsync(string actorRoleName)
        {
            // This aims to replicate Rust's logic: "Returns list of roles that the current user can assign, 
            // showing only permissions they possess."
            // The Rust query is complex: it filters roles to only those where the actor possesses ALL permissions of that role.
            try
            {
                // Eagerly loads related RolePermissions and their associated Permissions for the actor's role.
                var actorRole = await _context.Roles
                                    .Include(r => r.RolePermissions)
                                    .ThenInclude(rp => rp.Permission)
                                    .FirstOrDefaultAsync(r => r.Name == actorRoleName);

                if (actorRole == null)
                {
                    _logger.LogWarning("Actor role {ActorRoleName} not found for GetRolesWithPermissionsAsync.", actorRoleName);
                    return new List<RoleWithPermissionsDto>();
                }
                // Creates a HashSet of the actor's permission names for efficient lookup.
                var actorPermissionNames = actorRole.RolePermissions.Select(rp => rp.Permission.Name).ToHashSet();

                var allRoles = await _context.Roles
                    // Eagerly loads permissions for all roles.
                    .Include(r => r.RolePermissions)
                    .ThenInclude(rp => rp.Permission)
                    .OrderBy(r => r.Name)
                    .ToListAsync();
                
                var resultRoles = new List<RoleWithPermissionsDto>();

                foreach (var role in allRoles)
                {
                    var rolePermissionNames = role.RolePermissions.Select(rp => rp.Permission.Name).ToList();
                    // Check if actor has all permissions of this role
                    // This logic ensures that an admin can only manage roles whose permissions they themselves possess.
                    if (rolePermissionNames.All(pName => actorPermissionNames.Contains(pName)))
                    {
                        resultRoles.Add(new RoleWithPermissionsDto
                        {
                            Name = role.Name,
                            Permissions = rolePermissionNames.OrderBy(p => p).ToList()
                        });
                    }
                }
                return resultRoles;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting roles with permissions for actor role {ActorRoleName}", actorRoleName);
                return new List<RoleWithPermissionsDto>();
            }
        }

        // Creates a new role with specified permissions.
        // The 'actorRoleName' is used to enforce that the creator cannot assign permissions they don't have.
        public async Task<(bool Success, RoleResponseDto? Role, string Message)> CreateRoleAsync(CreateRoleRequestDto request, string actorRoleName)
        {
            // Using a database transaction ensures that all operations (creating role, assigning permissions) either complete successfully or are rolled back.
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var existingRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == request.Name);
                if (existingRole != null)
                {
                    return (false, null, $"Role '{request.Name}' already exists.");
                }

                // Get actor's permissions
                var actorDbRole = await _context.Roles
                    .Include(r => r.RolePermissions)
                    .ThenInclude(rp => rp.Permission)
                    .FirstOrDefaultAsync(r => r.Name == actorRoleName);

                if (actorDbRole == null)
                {
                    _logger.LogWarning("Actor role {ActorRoleName} not found during CreateRoleAsync.", actorRoleName);
                    return (false, null, "Actor role not found, cannot verify permissions.");
                }
                var actorPermissionNames = actorDbRole.RolePermissions.Select(rp => rp.Permission.Name).ToHashSet();

                // Check if actor has all requested permissions for the new role
                // This is a critical security check.
                foreach (var requestedPermName in request.Permissions)
                {
                    if (!actorPermissionNames.Contains(requestedPermName))
                    {
                        return (false, null, $"Cannot assign permission '{requestedPermName}' to new role as you do not possess it.");
                    }
                }

                // Create the new role
                var newRole = new Role { Name = request.Name };
                _context.Roles.Add(newRole);
                await _context.SaveChangesAsync(); // Save to generate newRole.Id by the database.

                var rolePermissionsToAdd = new List<RolePermission>();
                var newRolePermissionNames = new List<string>();

                foreach (var permName in request.Permissions.Distinct()) // Ensure distinct permissions
                {
                    var permission = await _context.Permissions.FirstOrDefaultAsync(p => p.Name == permName);
                    if (permission == null)
                    {
                        await transaction.RollbackAsync();
                        return (false, null, $"Permission '{permName}' not found.");
                    }
                    rolePermissionsToAdd.Add(new RolePermission { RoleId = newRole.Id, PermissionId = permission.Id });
                    newRolePermissionNames.Add(permName);
                }

                if (rolePermissionsToAdd.Any())
                {
                    _context.RolePermissions.AddRange(rolePermissionsToAdd);
                    await _context.SaveChangesAsync();
                }

                await transaction.CommitAsync(); // Commit the transaction if all operations were successful.
                _logger.LogInformation("Role {RoleName} created successfully by actor with role {ActorRoleName}", request.Name, actorRoleName);
                
                return (true, new RoleResponseDto { Name = newRole.Name, Permissions = newRolePermissionNames.OrderBy(p=>p).ToList() }, "Role created successfully.");
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error creating role {RoleName} by actor {ActorRoleName}. Transaction rolled back.", request.Name, actorRoleName);
                return (false, null, $"An unexpected error occurred: {ex.Message}");
            }
        }

        public async Task<(bool Success, RoleResponseDto? Role, string Message)> UpdateRoleAsync(string roleName, UpdateRoleRequestDto request, string actorRoleName)
        {
            // More nuanced checks for protected roles might be needed.
            // E.g., "Admin" role might have certain permissions that cannot be removed.
            // "Unconfirmed", "Blocked" roles typically shouldn't have their permissions managed this way.
            // These are "guard clauses" to prevent modification of system-critical roles.
            var nonEditableRoles = new[] { "Unconfirmed", "Blocked" };
            if (nonEditableRoles.Contains(roleName, StringComparer.OrdinalIgnoreCase))
            {
                 return (false, null, $"Role '{roleName}' permissions cannot be directly updated.");
            }

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var roleToUpdate = await _context.Roles
                    .Include(r => r.RolePermissions) // Include existing permissions to remove them
                    .FirstOrDefaultAsync(r => r.Name == roleName);

                if (roleToUpdate == null)
                {
                    return (false, null, $"Role '{roleName}' not found.");
                }

                // Get actor's permissions
                var actorDbRole = await _context.Roles
                    .Include(r => r.RolePermissions)
                    .ThenInclude(rp => rp.Permission)
                    .FirstOrDefaultAsync(r => r.Name == actorRoleName);

                if (actorDbRole == null)
                {
                    _logger.LogWarning("Actor role {ActorRoleName} not found during UpdateRoleAsync.", actorRoleName);
                    await transaction.RollbackAsync(); // Rollback before returning
                    return (false, null, "Actor role not found, cannot verify permissions.");
                }
                var actorPermissionNames = actorDbRole.RolePermissions.Select(rp => rp.Permission.Name).ToHashSet();

                // Check if actor has all permissions they are trying to set for the target role
                foreach (var requestedPermName in request.Permissions)
                {
                    if (!actorPermissionNames.Contains(requestedPermName))
                    {
                        await transaction.RollbackAsync();
                        return (false, null, $"Cannot assign permission '{requestedPermName}' as you do not possess it.");
                    }
                }
                
                // Additional check: If updating the "Admin" role, ensure critical permissions are not removed by a non-Admin or by mistake.
                // This is a simplified safeguard. A more robust system might have immutable permissions for certain roles.
                List<string> finalPermissionsForRole = request.Permissions.Distinct().ToList();

                if (roleToUpdate.Name.Equals("Admin", StringComparison.OrdinalIgnoreCase))
                {
                    var essentialAdminPerms = new[] { "manage_roles", "manage_users" }; // Example
                    foreach (var essentialPerm in essentialAdminPerms)
                    {
                        if (!finalPermissionsForRole.Contains(essentialPerm))
                        {
                            // If actor is also Admin and has this perm, they could choose to remove it.
                            // But if actor is NOT Admin, they shouldn't be able to strip Admin of essential perms.
                            // This logic needs to be very careful. For now, if it's Admin role, we ensure essential perms stay if actor has them.
                            if (actorPermissionNames.Contains(essentialPerm)) {
                                finalPermissionsForRole.Add(essentialPerm);
                                _logger.LogWarning("Ensured essential permission '{EssentialPerm}' is part of Admin role update by {ActorRoleName}", essentialPerm, actorRoleName);
                            } else {
                                // Actor doesn't have an essential Admin perm they are trying to remove from Admin role. This is problematic.
                                // Or, they are trying to set Admin role without an essential perm they don't have.
                                // This indicates a flaw in the request or actor's ability.
                                 _logger.LogWarning("Actor {ActorRoleName} attempting to modify Admin role without possessing/assigning essential permission {EssentialPerm}", actorRoleName, essentialPerm);
                                // For now, we'll let the earlier check (actor must possess all perms they assign) handle this.
                                // If an essential perm is removed from the list, and the actor didn't have it, the above check would fail.
                                // If actor *had* it and removed it from Admin, that's a conscious choice (though risky).
                            }
                        }
                    }
                    finalPermissionsForRole = finalPermissionsForRole.Distinct().ToList();
                }


                // Clear existing permissions for the role
                _context.RolePermissions.RemoveRange(roleToUpdate.RolePermissions);
                // Must save changes here if we are to avoid PK violations when re-adding same permissions
                // However, it's often cleaner to calculate the diff.
                // For simplicity as in Rust: remove all, then add all from request.
                // await _context.SaveChangesAsync(); // This might be too early if subsequent ops fail.

                var newRolePermissionLinks = new List<RolePermission>();
                foreach (var permName in finalPermissionsForRole) // Use the potentially adjusted list
                {
                    var permission = await _context.Permissions.FirstOrDefaultAsync(p => p.Name == permName);
                    if (permission == null)
                    {
                        await transaction.RollbackAsync();
                        return (false, null, $"Permission '{permName}' not found.");
                    }
                    newRolePermissionLinks.Add(new RolePermission { RoleId = roleToUpdate.Id, PermissionId = permission.Id });
                }
                
                // Efficiently update: remove old, add new.
                // The current approach (remove all existing, then add all new) is simpler to implement.
                roleToUpdate.RolePermissions.Clear(); // Clear the collection in memory
                _context.RolePermissions.RemoveRange(_context.RolePermissions.Where(rp => rp.RoleId == roleToUpdate.Id)); // Remove from DB context tracking
                // This ensures that existing permissions are removed before new ones are added.

                if (newRolePermissionLinks.Any())
                {
                    _context.RolePermissions.AddRange(newRolePermissionLinks);
                }
                
                await _context.SaveChangesAsync(); // This saves all changes: role permission removals and additions.
                await transaction.CommitAsync();
                _logger.LogInformation("Role {RoleName} updated successfully by actor with role {ActorRoleName}", roleName, actorRoleName);

                return (true, new RoleResponseDto { Name = roleToUpdate.Name, Permissions = finalPermissionsForRole.OrderBy(p=>p).ToList() }, "Role updated successfully.");
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error updating role {RoleName} by actor {ActorRoleName}", roleName, actorRoleName);
                return (false, null, $"An unexpected error occurred: {ex.Message}");
            }
        }

        public async Task<(bool Success, string Message)> DeleteRoleAsync(string roleName)
        {
            // Protected roles that cannot be deleted.
            var protectedRoles = new[] { "Admin", "Editor", "User", "Unconfirmed", "Blocked" };
            if (protectedRoles.Contains(roleName, StringComparer.OrdinalIgnoreCase))
            {
                return (false, $"Protected role '{roleName}' cannot be deleted.");
            }

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var roleToDelete = await _context.Roles.FirstOrDefaultAsync(r => r.Name == roleName);
                if (roleToDelete == null)
                {
                    await transaction.RollbackAsync(); // Nothing to do, role doesn't exist
                    return (false, $"Role '{roleName}' not found.");
                }

                var defaultUserRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "User");
                if (defaultUserRole == null)
                {
                    _logger.LogError("Critical: Default 'User' role not found. Cannot reassign users from deleted role {DeletedRoleName}.", roleName);
                    await transaction.RollbackAsync();
                    return (false, "System configuration error: Default 'User' role missing. Role deletion aborted.");
                }
                
                // Cannot delete the 'User' role itself if it was somehow passed despite protected check (e.g. casing)
                if (roleToDelete.Id == defaultUserRole.Id) {
                    await transaction.RollbackAsync();
                    return (false, "The default 'User' role cannot be deleted.");
                }

                // Find users with the role to be deleted and update their RoleId
                // This is more efficient than loading all user entities
                // ExecuteUpdateAsync performs a bulk update operation directly in the database.
                var usersToUpdateQuery = _context.Users.Where(u => u.RoleId == roleToDelete.Id);
                await usersToUpdateQuery.ExecuteUpdateAsync(setters => setters.SetProperty(u => u.RoleId, defaultUserRole.Id));
                
                _logger.LogInformation("Users previously assigned to role {DeletedRoleName} have been reassigned to {DefaultUserRoleName}.", roleName, defaultUserRole.Name);

                // Remove role permissions associated with the role
                var rolePermissionsToRemove = _context.RolePermissions.Where(rp => rp.RoleId == roleToDelete.Id);
                _context.RolePermissions.RemoveRange(rolePermissionsToRemove);
                
                // Remove the role itself
                _context.Roles.Remove(roleToDelete);

                await _context.SaveChangesAsync(); // Saves all changes: user updates, RolePermission removals, Role removal
                await transaction.CommitAsync();

                _logger.LogInformation("Role {RoleName} deleted successfully.", roleName);
                return (true, $"Role '{roleName}' deleted successfully. Affected users reassigned to '{defaultUserRole.Name}' role.");
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error deleting role {RoleName}", roleName);
                return (false, $"An unexpected error occurred while deleting role '{roleName}': {ex.Message}");
            }
        }

        // Assigns a specified role to a target user, performed by an assigner user.
        public async Task<(bool Success, string Message)> AssignRoleAsync(int assignerUserId, int targetUserId, string newRoleName)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var assignerUser = await _context.Users
                    .Include(u => u.Role)
                        // Deeply include permissions of the assigner's role to check their capabilities.
                    .ThenInclude(r => r.RolePermissions)
                    .ThenInclude(rp => rp.Permission)
                    .FirstOrDefaultAsync(u => u.UserId == assignerUserId);

                if (assignerUser == null) return (false, "Assigner user not found.");

                var targetUser = await _context.Users.FindAsync(targetUserId);
                if (targetUser == null) return (false, "Target user not found.");

                var newRole = await _context.Roles
                    .Include(r => r.RolePermissions)
                    .ThenInclude(rp => rp.Permission)
                    .FirstOrDefaultAsync(r => r.Name == newRoleName);
                if (newRole == null) return (false, $"Role '{newRoleName}' not found.");

                // 1. Check if assigner has 'manage_roles' permission
                // This is a fundamental permission check for role assignment.
                var assignerPermissions = assignerUser.Role.RolePermissions.Select(rp => rp.Permission.Name).ToHashSet();
                if (!assignerPermissions.Contains("manage_roles")) // Assuming "manage_roles" is the permission name
                {
                    return (false, "Assigner does not have permission to manage roles.");
                }

                // 2. Check if assigner has all permissions of the target role they are trying to assign
                // Ensures an assigner cannot grant permissions they do not possess themselves.
                var newRolePermissions = newRole.RolePermissions.Select(rp => rp.Permission.Name).ToHashSet();
                foreach (var permNameInNewRole in newRolePermissions)
                {
                    if (!assignerPermissions.Contains(permNameInNewRole))
                    {
                        return (false, $"Assigner cannot assign role '{newRoleName}' because it includes permission '{permNameInNewRole}' which assigner does not possess.");
                    }
                }
                
                // Prevent assigning Admin role by non-Admins, or self-assigning Admin if not already Admin
                // This is a critical safeguard.
                // Protecting the 'Admin' role is crucial for system security.
                if (newRole.Name.Equals("Admin", StringComparison.OrdinalIgnoreCase) &&
                    !assignerUser.Role.Name.Equals("Admin", StringComparison.OrdinalIgnoreCase))
                {
                    return (false, "Only an Admin can assign the Admin role.");
                }


                // Update target user's role
                targetUser.RoleId = newRole.Id;

                // If assigning "Blocked" role, also update disabled status
                // Special handling for the "Blocked" role to ensure user account is also marked as disabled.
                if (newRole.Name.Equals("Blocked", StringComparison.OrdinalIgnoreCase))
                {
                    targetUser.Disabled = true;
                    targetUser.DisabledAt = DateTime.UtcNow;
                    targetUser.DisabledByUserId = assignerUserId;
                }
                else
                {
                    // If assigning any other role, ensure user is not disabled (unless it's a specific "DisabledUser" role not "Blocked")
                    // This logic might need refinement based on how "Disabled" status interacts with roles other than "Blocked".
                    // For now, if not "Blocked", ensure they are not marked as disabled by this operation.
                    if (targetUser.Role.Name != "Blocked" && targetUser.Disabled && targetUser.DisabledByUserId == assignerUserId) {
                         // If assigner previously blocked them and now assigns a non-blocked role, unblock.
                        targetUser.Disabled = false;
                        targetUser.DisabledAt = null;
                        targetUser.DisabledByUserId = null;
                    } else if (targetUser.Role.Name != "Blocked" && targetUser.Disabled) {
                        // If user is disabled for other reasons, assigning a role doesn't automatically re-enable them.
                        // This part of logic depends on business rules for 'disabled' flag.
                    }
                }

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation("User {TargetUserId} assigned role {NewRoleName} by user {AssignerUserId}", targetUserId, newRoleName, assignerUserId);
                return (true, $"User '{targetUser.Username}' successfully assigned role '{newRoleName}'.");
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error assigning role {NewRoleName} to user {TargetUserId} by assigner {AssignerUserId}", newRoleName, targetUserId, assignerUserId);
                return (false, $"An unexpected error occurred: {ex.Message}");
            }
        }

        // Blocks or unblocks a target user, performed by an actor user.
        public async Task<(bool Success, string Message)> BlockUserAsync(int actorUserId, int targetUserId, bool block)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var actorUser = await _context.Users
                    .Include(u => u.Role)
                    .ThenInclude(r => r.RolePermissions)
                    .ThenInclude(rp => rp.Permission)
                    .FirstOrDefaultAsync(u => u.UserId == actorUserId);

                if (actorUser == null)
                {
                    await transaction.RollbackAsync();
                    return (false, "Actor user not found.");
                }

                var targetUser = await _context.Users.Include(u => u.Role).FirstOrDefaultAsync(u => u.UserId == targetUserId);
                if (targetUser == null)
                {
                    await transaction.RollbackAsync();
                    return (false, "Target user not found.");
                }

                var actorPermissions = actorUser.Role.RolePermissions.Select(rp => rp.Permission.Name).ToHashSet();
                // Requires 'block_users' permission.
                if (!actorPermissions.Contains("block_users"))
                {
                    await transaction.RollbackAsync();
                    return (false, "Actor does not have permission to block or unblock users.");
                }

                // Prevent non-Admins from blocking Admins.
                // Rust also checks if target has 'manage_users' permission.
                // A user with 'manage_users' might be an Admin or a high-level Moderator.
                var targetUserPermissions = await _context.RolePermissions
                                                // Check permissions of the target user's current role.
                                                .Where(rp => rp.RoleId == targetUser.RoleId)
                                                .Select(rp => rp.Permission.Name)
                                                .ToListAsync();
                
                if (targetUserPermissions.Contains("manage_users") && !actorUser.Role.Name.Equals("Admin", StringComparison.OrdinalIgnoreCase))
                {
                     await transaction.RollbackAsync();
                    // Prevents non-Admins from blocking users who have 'manage_users' permission (typically other admins or moderators).
                    return (false, "Cannot block a user with 'manage_users' permission unless you are an Admin.");
                }
                
                if (actorUserId == targetUserId && block) // Prevent self-blocking
                {
                    await transaction.RollbackAsync();
                    return (false, "You cannot block yourself.");
                }

                // Update user's disabled status and potentially their role.
                targetUser.Disabled = block;
                if (block)
                {
                    targetUser.DisabledAt = DateTime.UtcNow;
                    targetUser.DisabledByUserId = actorUserId;
                    
                    var blockedRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "Blocked");
                    // If a "Blocked" role exists, assign it to the user.
                    if (blockedRole != null && targetUser.RoleId != blockedRole.Id)
                    {
                        targetUser.RoleId = blockedRole.Id;
                         _logger.LogInformation("User {TargetUserId} role changed to 'Blocked'.", targetUserId);
                    }
                    else if (blockedRole == null)
                    {
                        _logger.LogWarning("Role 'Blocked' not found. User {TargetUserId} disabled but role not changed to 'Blocked'.", targetUserId);
                    }
                }
                else // Unblocking
                {
                    targetUser.DisabledAt = null;
                    targetUser.DisabledByUserId = null;
                    

                    // If unblocking, and user was in "Blocked" role, revert them to a default role like "User".
                    if (targetUser.Role.Name.Equals("Blocked", StringComparison.OrdinalIgnoreCase))
                    {
                        var userRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "User");
                        if (userRole != null)
                        {
                            targetUser.RoleId = userRole.Id;
                            _logger.LogInformation("User {TargetUserId} role reverted to 'User' upon unblocking.", targetUserId);
                        }
                        else
                        {
                             _logger.LogError("Critical: Default 'User' role not found. Cannot revert role for unblocked user {TargetUserId}.", targetUserId);
                        }
                    }
                }

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation("User {TargetUserId} ({TargetUsername}) has been {Action} by user {ActorUserId} ({ActorUsername})",
                    targetUserId, targetUser.Username, block ? "blocked" : "unblocked", actorUserId, actorUser.Username);
                return (true, $"User '{targetUser.Username}' has been successfully {(block ? "blocked" : "unblocked")}.");
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error {Action} user {TargetUserId} by actor {ActorUserId}", block ? "blocking" : "unblocking", targetUserId, actorUserId);
                return (false, $"An unexpected error occurred: {ex.Message}");
            }
        }
    }
}

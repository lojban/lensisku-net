using System.Collections.Generic;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used to respond with a list of roles, typically including their permissions.
    public class UserRolesResponseDto
    {
        // A list of RoleWithPermissionsDto objects, each representing a role and its permissions.
        public List<RoleWithPermissionsDto> Roles { get; set; } = new List<RoleWithPermissionsDto>();
    }
}

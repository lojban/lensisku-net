using System.Collections.Generic;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used to represent a role along with its associated permissions.
    // It's often used when displaying role details or managing role assignments.
    public class RoleWithPermissionsDto
    {
        public string Name { get; set; } = string.Empty;
        // A list of permission names associated with this role.
        public List<string> Permissions { get; set; } = new List<string>();
    }
}

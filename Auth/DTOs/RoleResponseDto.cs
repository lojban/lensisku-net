using System.Collections.Generic;

namespace Lensisku.Auth.DTOs
{
    // This DTO is structurally identical to RoleWithPermissionsDto.
    // It's used as a response when role information (name and permissions) is returned by the API.
    // It's created separately to maintain a 1:1 mapping with Rust DTOs for now.
    public class RoleResponseDto
    {
        public string Name { get; set; } = string.Empty;
        public List<string> Permissions { get; set; } = new List<string>();
    }
}
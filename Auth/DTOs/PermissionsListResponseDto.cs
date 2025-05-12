using System.Collections.Generic;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used to respond with a list of available permissions.
    public class PermissionsListResponseDto
    {
        // A list of PermissionInfoDto objects, each describing a permission.
        public List<PermissionInfoDto> Permissions { get; set; } = new List<PermissionInfoDto>();
    }
}

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to create a new role.
    public class CreateRoleRequestDto
    {
        [Required]
        [StringLength(50, MinimumLength = 2)]
        // The name of the new role to be created.
        public string Name { get; set; } = string.Empty;

        [Required]
        // A list of permission names to be assigned to the new role.
        public List<string> Permissions { get; set; } = new List<string>();
    }
}

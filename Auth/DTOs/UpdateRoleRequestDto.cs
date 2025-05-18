using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to update an existing role, specifically its permissions.
    public class UpdateRoleRequestDto
    {
        [Required]
        public List<string> Permissions { get; set; } = new List<string>();
    }
}
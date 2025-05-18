using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to assign a role to a user.
    public class AssignRoleRequestDto
    {
        [Required]
        // The ID of the user to whom the role will be assigned.
        public int UserId { get; set; }

        [Required]
        [StringLength(50, MinimumLength = 2)]
        // The name of the role to assign.
        public string Role { get; set; } = string.Empty;
    }
}

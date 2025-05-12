using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to block or unblock a user.
    public class BlockUserRequestDto
    {
        [Required]
        // The ID of the user to be blocked or unblocked.
        public int UserId { get; set; }

        [Required]
        // A boolean flag indicating whether to block (true) or unblock (false) the user.
        public bool Block { get; set; }
    }
}

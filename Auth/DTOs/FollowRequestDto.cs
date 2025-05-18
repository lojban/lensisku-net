using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    // This DTO is used for requests to follow or unfollow another user.
    public class FollowRequestDto
    {
        [Required]
        // The ID of the user to be followed or unfollowed.
        public int FolloweeId { get; set; }

        [Required]
        // A boolean flag indicating the desired action: true to follow, false to unfollow.
        public bool Follow { get; set; }
    }
}

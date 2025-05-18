using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace Lensisku.Auth.Models
{
    // This class represents a 'Follow' relationship entity, mapping to the "follows" table.
    // It signifies that one user (Follower) is following another user (Followee).
    [Table("follows")] // Matches Rust's 'follows' table
    public class Follow
    {
        // Composite Primary Key configured in AppDbContext
        // This means the combination of FollowerId and FolloweeId uniquely identifies a follow relationship.
        [Column("follower_id")]
        public int FollowerId { get; set; }
        // Navigation property to the User who is the follower.
        public virtual User FollowerUser { get; set; } = null!;

        [Column("followee_id")]
        public int FolloweeId { get; set; }
        // Navigation property to the User who is being followed.
        public virtual User FolloweeUser { get; set; } = null!;

        [Column("created_at")]
        // Timestamp indicating when the follow relationship was established.
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}

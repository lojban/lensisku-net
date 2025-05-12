using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Lensisku.Auth.Models
{
    // This class represents a 'User' entity in the application, mapping to the "users" table in the database.
    // It holds all information related to a user account.
    [Table("users")]
    public class User
    {
        [Key]
        // [Key] attribute marks UserId as the primary key.
        // [Column("userid")] explicitly maps this property to the "userid" column.
        [Column("userid")]
        public int UserId { get; set; }

        [Required]
        [MaxLength(255)] // Assuming a reasonable max length
        [Column("username")]
        public string Username { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        [MaxLength(255)]
        [Column("email")]
        public string Email { get; set; } = string.Empty;

        [Required]
        [Column("password")] // Stores the hashed password
        // Stores the hashed password, not the plain text password, for security.
        public string PasswordHash { get; set; } = string.Empty;

        [Required]
        [Column("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [Column("followers")]
        // Denormalized count of followers for quick retrieval. Could also be calculated via a query on the Follows table.
        public int Followers { get; set; } = 0;

        [Required]
        [Column("role_id")]
        // Foreign key to the Roles table.
        public int RoleId { get; set; }
        public virtual Role Role { get; set; } = null!; // Navigation property

        [Required]
        [Column("email_confirmed")]
        public bool EmailConfirmed { get; set; } = false;

        [Column("email_confirmation_token")]
        // Token used for verifying the user's email address.
        public string? EmailConfirmationToken { get; set; }

        [Column("email_confirmation_sent_at")]
        // Timestamp of when the email confirmation token was sent.
        public DateTime? EmailConfirmationSentAt { get; set; }

        [Column("disabled")]
        // Flag indicating if the user account is disabled (e.g., blocked by an admin).
        public bool Disabled { get; set; } = false;

        [Column("disabled_at")]
        public DateTime? DisabledAt { get; set; }

        [Column("disabled_by")]
        // ID of the user (typically an admin) who disabled this account.
        public int? DisabledByUserId { get; set; } // Foreign key to users.userid

        // Optional profile information.
        [MaxLength(255)]
        [Column("realname")]
        public string? RealName { get; set; }

        [MaxLength(512)]
        [Column("url")]
        public string? Url { get; set; }

        [Column("personal", TypeName = "text")]
        public string? Personal { get; set; }
        
        [Column("votesize")]
        public float VoteSize { get; set; } = 1.0f;

        // Navigation properties for Follows
        // These define the relationships for the "Follows" functionality.
        // A User can be a follower (Following) and can be followed by others (FollowersList).
        // [InverseProperty] attribute helps EF Core correctly map these relationships when there are multiple
        // navigation properties between two entities (User and Follow in this case).
        [InverseProperty("FollowerUser")]
        public virtual ICollection<Follow> Following { get; set; } = new List<Follow>();

        [InverseProperty("FolloweeUser")]
        public virtual ICollection<Follow> FollowersList { get; set; } = new List<Follow>();

        // One-to-one relationship with UserProfileImage. A user can have one profile image.
        // Navigation property for one-to-one relationship with UserProfileImage
        public virtual UserProfileImage? ProfileImage { get; set; }

        // One-to-one relationship with UserSettings. A user can have one set of application settings.
        // Navigation property for one-to-one relationship with UserSettings
        public virtual UserSettings? Settings { get; set; }
    }
}
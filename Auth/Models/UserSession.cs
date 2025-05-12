using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Lensisku.Auth.Models
{
    // This class represents a 'UserSession' entity, mapping to the "user_sessions" table.
    // It's used to track user login sessions, including IP address, user agent, and session times.
    [Table("user_sessions")]
    public class UserSession
    {
        [Key]
        // [DatabaseGenerated(DatabaseGeneratedOption.Identity)] specifies that the database generates a value for this property on insert (e.g., auto-incrementing ID).
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [Column("id")]
        public long Id { get; set; } // Matches i64 from Rust session service

        [Required]
        [Column("user_id")]
        public int UserId { get; set; }
        // 'public virtual User User { get; set; } = null!;' is a navigation property.
        // It defines a relationship to the 'User' entity (one session belongs to one user).
        public virtual User User { get; set; } = null!;

        [Required]
        [Column("session_uuid")]
        public Guid SessionUuid { get; set; } // Matches Uuid from Rust

        [Required]
        [MaxLength(255)]
        [Column("ip_address")]
        public string IpAddress { get; set; } = string.Empty;

        [MaxLength(512)]
        [Column("user_agent")]
        public string? UserAgent { get; set; }

        [Required]
        [Column("started_at")]
        public DateTime StartedAt { get; set; } = DateTime.UtcNow;

        [Column("last_activity_at")]
        public DateTime? LastActivityAt { get; set; }

        [Column("ended_at")]
        public DateTime? EndedAt { get; set; }
    }
}
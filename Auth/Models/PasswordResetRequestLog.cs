using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Lensisku.Auth.Models
{
    // This class represents a log entry for a password reset request, mapping to the "password_reset_requests" table.
    // It tracks requests to prevent abuse and manage the lifecycle of reset tokens.
    [Table("password_reset_requests")]
    public class PasswordResetRequestLog
    {
        // Primary key for the log entry.
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [Column("id")]
        public int Id { get; set; }

        [Required]
        [MaxLength(255)]
        [Column("email")]
        public string Email { get; set; } = string.Empty;

        // A unique session ID associated with this reset request, often part of the reset link.
        [Required]
        [MaxLength(36)] // UUID length
        [Column("session_id")]
        public string SessionId { get; set; } = string.Empty;

        // The actual reset token sent to the user (e.g., in the reset link).
        [Required]
        [MaxLength(64)] // Assuming a reasonable max token length
        [Column("token")]
        public string Token { get; set; } = string.Empty;

        // Expiry time for the reset token.
        
        [Required]
        [Column("token_expiry")] // Store as DateTime in DB, map from/to i64 if needed for direct port
        public DateTime TokenExpiry { get; set; }

        [Required]
        [Column("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Flag indicating whether the reset token has been used.
        [Required]
        [Column("used")]
        public bool Used { get; set; } = false;

        // Timestamp of when the token was used.
        [Column("used_at")]
        public DateTime? UsedAt { get; set; }
    }
}
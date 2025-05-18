using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Lensisku.Auth.Models
{
    // This class represents a log or record for password change verification attempts,
    // typically used when an authenticated user wants to change their password and needs to verify via a code.
    // It maps to the "password_change_verifications" table.
    [Table("password_change_verifications")]
    public class PasswordChangeVerification
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [Column("id")]
        // Primary key for the verification record.
        public int Id { get; set; }

        [Required]
        [Column("user_id")]
        // Foreign key to the User who is attempting the password change.
        public int UserId { get; set; }
        public virtual User User { get; set; } = null!;

        [Required]
        [MaxLength(36)] // UUID length
        [Column("verification_id")]
        // A unique identifier for this specific verification attempt (e.g., a GUID).
        public string VerificationId { get; set; } = string.Empty;

        [Required]
        [MaxLength(10)] // Assuming max length for verification code (Rust uses 6)
        [Column("verification_code")]
        // The short code (e.g., 6-digit number) sent to the user for verification.
        public string VerificationCode { get; set; } = string.Empty;

        [Required]
        [Column("expires_at")]
        // Timestamp indicating when this verification code/attempt expires.
        public DateTime ExpiresAt { get; set; }

        [Column("completed_at")]
        // Timestamp indicating when the verification was successfully completed (password changed). Null if not completed.
        public DateTime? CompletedAt { get; set; }

        [Required]
        [Column("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
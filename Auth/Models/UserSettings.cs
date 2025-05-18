using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Lensisku.Auth.Models
{
    // This class represents user-specific settings, mapping to the "user_settings" table.
    // It demonstrates a one-to-one relationship with the User entity.
    [Table("user_settings")]
    public class UserSettings
    {
        [Key]
        [Column("user_id")]
        // UserId is both the primary key for this table and a foreign key referencing the User table.
        public int UserId { get; set; }
        // Navigation property back to the User entity.
        public virtual User User { get; set; } = null!;

        [Required]
        [Column("optimal_retention")]
        // An example setting, perhaps for a learning or recommendation system.
        // Default value is 0.9.
        public double OptimalRetention { get; set; } = 0.9;

        [Required]
        [Column("last_calculated")]
        // Timestamp indicating when these settings were last calculated or updated.
        public DateTime LastCalculated { get; set; } = DateTime.UtcNow;
    }
}

using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Lensisku.Auth.Models
{
    // This class represents a user's profile image, mapping to the "user_profile_images" table.
    // It demonstrates a one-to-one relationship with the User entity.
    [Table("user_profile_images")]
    public class UserProfileImage
    {
        [Key]
        [Column("user_id")]
        // UserId is both the primary key for this table and a foreign key referencing the User table.
        public int UserId { get; set; }
        // Navigation property back to the User entity.
        public virtual User User { get; set; } = null!;

        [Required]
        [Column("image_data")]
        // The raw binary data of the image. Storing images directly in the database can impact performance
        // and scalability; alternative approaches include storing images in file systems or cloud storage
        // and saving only the URL/path in the database.
        public byte[] ImageData { get; set; } = Array.Empty<byte>();

        [Required]
        [MaxLength(50)] // Max length for MIME types e.g., "image/jpeg", "image/png"
        [Column("mime_type")]
        // The MIME type of the image (e.g., "image/jpeg", "image/png"), important for rendering it correctly.
        public string MimeType { get; set; } = string.Empty;

        [Required]
        [Column("updated_at")]
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
}
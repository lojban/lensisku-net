using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Lensisku.Auth.Models
{
    // This class represents a 'Permission' entity, mapping to the "permissions" table.
    // Permissions define specific actions or access rights within the application (e.g., "manage_users", "create_post").
    [Table("permissions")]
    public class Permission
    {
        // Primary key for the permission.
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        [Column("name")]
        // The unique name of the permission (e.g., "edit_articles").
        public string Name { get; set; } = string.Empty;

        [MaxLength(500)]
        [Column("description")]
        // An optional description of what the permission allows.
        public string? Description { get; set; }

        // Navigation property for many-to-many relationship with Role
        // This links to the RolePermission join table, defining which roles have this permission.
        public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
    }
}

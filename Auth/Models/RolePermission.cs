using System.ComponentModel.DataAnnotations.Schema;

namespace Lensisku.Auth.Models
{
    // This class represents the join table for a many-to-many relationship between 'Role' and 'Permission'.
    // Join table for the many-to-many relationship between Role and Permission
    // Each instance of RolePermission links one Role to one Permission.
    [Table("role_permissions")]
    public class RolePermission
    {
        // Composite primary key will be configured in DbContext using HasKey(rp => new { rp.RoleId, rp.PermissionId })
        // This means the combination of RoleId and PermissionId must be unique.
        [Column("role_id")]
        public int RoleId { get; set; }

        [Column("permission_id")]
        public int PermissionId { get; set; }
        // Navigation property back to the Permission entity.
        public virtual Permission Permission { get; set; } = null!;
    }
}

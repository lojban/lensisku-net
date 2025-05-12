// These 'using' directives import namespaces for data annotations.
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Lensisku.Auth.Models
{
    // This class represents a 'Role' entity in the application.
    // This entity represents a defined role in the system.
    // The actual role assigned to a user is stored as a string in User.RoleName,
    // matching the 'Name' property here. This table helps manage available roles and their permissions.
    // [Table("roles")] attribute maps this class to the "roles" table in the database.
    // This is an Entity Framework Core (EF Core) convention for Code-First or Database-First mapping.
    [Table("roles")] // A table to store role definitions, if not existing.
                     // Or, this could be an abstraction if roles are purely string-based in DB.
                     // Given Rust's create_role/update_role, a managed list of roles is implied.
    public class Role
    {
        [Key]
        [Column("id")]
        // Properties in EF Core models map to columns in the database table.
        // [Key] attribute marks 'Id' as the primary key for the 'roles' table.
        public int Id { get; set; } // Synthetic PK for the roles table

        [Required]
        [MaxLength(50)]
        [Column("name")] // This name should be unique and matches User.RoleName
        // [Required] attribute indicates that the 'Name' property cannot be null.
        // [MaxLength(50)] specifies the maximum length for the 'Name' string.
        // [Column("name")] explicitly maps this property to the "name" column in the database.
        public string Name { get; set; } = string.Empty;

        // Navigation property for many-to-many relationship with Permission
        // 'virtual ICollection<RolePermission>' defines a navigation property.
        // In EF Core, 'virtual' enables lazy loading (related entities are loaded from the database only when accessed).
        // This represents the 'many' side of a one-to-many relationship (Role to RolePermission)
        // and is part of a many-to-many relationship between Role and Permission, via the RolePermission join table.
        public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
        // If users are directly linked to this Role entity via a RoleId FK in Users table:
        // public virtual ICollection<User> Users { get; set; } = new List<User>();
    }
}
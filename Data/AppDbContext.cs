using Lensisku.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace Lensisku.Data
{
    // AppDbContext is the Entity Framework Core database context for this application.
    // It represents a session with the database and allows querying and saving data.
    // It inherits from DbContext.
    public class AppDbContext : DbContext
    {
        // Constructor that accepts DbContextOptions, allowing configuration (e.g., connection string)
        // to be passed in, typically via dependency injection.
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        // DbSet<TEntity> properties represent collections of entities that can be queried from the database.
        // Each DbSet maps to a table in the database.
        // The '= null!;' is a C# 8.0 nullable reference type feature, indicating to the compiler that
        // these properties will be initialized by EF Core and won't be null.
        public DbSet<User> Users { get; set; } = null!;
        public DbSet<Role> Roles { get; set; } = null!;
        public DbSet<Permission> Permissions { get; set; } = null!;
        // RolePermissions is the join table for the many-to-many relationship between Roles and Permissions.
        public DbSet<RolePermission> RolePermissions { get; set; } = null!;
        public DbSet<PasswordResetRequestLog> PasswordResetRequestLogs { get; set; } = null!;
        public DbSet<PasswordChangeVerification> PasswordChangeVerifications { get; set; } = null!;
        public DbSet<UserSession> UserSessions { get; set; } = null!;
        public DbSet<Follow> Follows { get; set; } = null!;
        public DbSet<UserProfileImage> UserProfileImages { get; set; } = null!;
        // UserSettings represents user-specific application settings.
        public DbSet<UserSettings> UserSettings { get; set; } = null!;

        // OnModelCreating is overridden to configure the EF Core model using the Fluent API.
        // This is where relationships, keys, constraints, and other database mappings are defined
        // if they are not (or cannot be) fully expressed using data annotations on the model classes.
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // User to Role (one-to-many)
            // User has RoleId, Role has many Users
            modelBuilder.Entity<User>()
                .HasOne(u => u.Role)
                .WithMany() // Assuming a Role can be assigned to many Users, but User entity doesn't have a collection of Users for a Role.
                // Defines a one-to-many relationship: one Role can have many Users, each User has one Role.
                .HasForeignKey(u => u.RoleId)
                .IsRequired();
            
            // Alternative if Role entity should have a list of users:
            // modelBuilder.Entity<Role>()
            //     .HasMany(r => r.Users)
            //     .WithOne(u => u.Role)
            //     .HasForeignKey(u => u.RoleId);


            // RolePermission (many-to-many between Role and Permission)
            modelBuilder.Entity<RolePermission>()
                // Configures a composite primary key for the RolePermission join table (RoleId, PermissionId).
                .HasKey(rp => new { rp.RoleId, rp.PermissionId }); // Composite primary key

            modelBuilder.Entity<RolePermission>()
                .HasOne(rp => rp.Role)
                .WithMany(r => r.RolePermissions)
                .HasForeignKey(rp => rp.RoleId);

            modelBuilder.Entity<RolePermission>()
                .HasOne(rp => rp.Permission)
                .WithMany(p => p.RolePermissions)
                .HasForeignKey(rp => rp.PermissionId);

            // PasswordChangeVerification to User (one-to-many)
            modelBuilder.Entity<PasswordChangeVerification>()
                .HasOne(pcv => pcv.User)
                .WithMany() // Assuming User doesn't need a collection of PasswordChangeVerifications
                .HasForeignKey(pcv => pcv.UserId)
                .IsRequired();

            // UserSession to User (one-to-many)
            modelBuilder.Entity<UserSession>()
                .HasOne(us => us.User)
                .WithMany() // Assuming User doesn't need a collection of UserSessions
                .HasForeignKey(us => us.UserId)
                .IsRequired();

            // Unique constraints (example for User username and email)
            // Ensures that Username and Email values are unique across all users.
            modelBuilder.Entity<User>()
                .HasIndex(u => u.Username)
                .IsUnique();

            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique();

            // Unique constraint for Role Name
            modelBuilder.Entity<Role>()
                .HasIndex(r => r.Name)
                .IsUnique();

            // Unique constraint for Permission Name
            modelBuilder.Entity<Permission>()
                .HasIndex(p => p.Name)
                .IsUnique();

            // Follow entity configuration
            modelBuilder.Entity<Follow>()
                // Configures a composite primary key for the Follow table (FollowerId, FolloweeId).
                .HasKey(f => new { f.FollowerId, f.FolloweeId }); // Composite primary key

            modelBuilder.Entity<Follow>()
                .HasOne(f => f.FollowerUser)
                .WithMany(u => u.Following) // Matches ICollection<Follow> Following in User.cs
                .HasForeignKey(f => f.FollowerId)
                // OnDelete(DeleteBehavior.Restrict) prevents cascade delete, which can be important
                // for complex relationships to avoid unintended data loss or database errors.
                .OnDelete(DeleteBehavior.Restrict); // Avoid cycles or multiple cascade paths

            modelBuilder.Entity<Follow>()
                .HasOne(f => f.FolloweeUser)
                .WithMany(u => u.FollowersList) // Matches ICollection<Follow> FollowersList in User.cs
                .HasForeignKey(f => f.FolloweeId)
                .OnDelete(DeleteBehavior.Restrict); // Avoid cycles or multiple cascade paths
                // These define the two sides of the many-to-many relationship for follows,
                // where a User can follow many other Users, and can be followed by many other Users,
                // through the Follow join entity.

            // UserProfileImage to User (one-to-one)
            modelBuilder.Entity<User>()
                .HasOne<UserProfileImage>() // User has one UserProfileImage
                .WithOne(upi => upi.User)   // UserProfileImage has one User
                .HasForeignKey<UserProfileImage>(upi => upi.UserId); // FK is in UserProfileImage

            // UserSettings to User (one-to-one)
            modelBuilder.Entity<User>()
                .HasOne<UserSettings>() // User has one UserSettings
                .WithOne(us => us.User) // UserSettings has one User
                .HasForeignKey<UserSettings>(us => us.UserId); // FK is in UserSettings
            
            // Default values or other configurations can be added here
            // Example: modelBuilder.Entity<User>().Property(u => u.CreatedAt).HasDefaultValueSql("NOW()");
            // However, C# default initializers are often preferred for DateTime.UtcNow
        }
    }
}

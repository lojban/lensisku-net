using Lensisku.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace Lensisku.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; } = null!;
        public DbSet<Permission> Permissions { get; set; } = null!;
        public DbSet<RolePermission> RolePermissions { get; set; } = null!;
        public DbSet<PasswordResetRequestLog> PasswordResetRequestLogs { get; set; } = null!;
        public DbSet<PasswordChangeVerification> PasswordChangeVerifications { get; set; } = null!;
        public DbSet<UserSession> UserSessions { get; set; } = null!;
        public DbSet<Follow> Follows { get; set; } = null!;
        public DbSet<UserProfileImage> UserProfileImages { get; set; } = null!;
        public DbSet<UserSettings> UserSettings { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure enum to string conversion for User.Role
            modelBuilder.Entity<User>()
                .Property(u => u.Role)
                .HasConversion<string>();

            // RolePermission (many-to-many between Role and Permission)
            modelBuilder.Entity<RolePermission>()
                .HasKey(rp => new { rp.RoleId, rp.PermissionId });


            modelBuilder.Entity<RolePermission>()
                .HasOne(rp => rp.Permission)
                .WithMany(p => p.RolePermissions)
                .HasForeignKey(rp => rp.PermissionId);

            // PasswordChangeVerification to User (one-to-many)
            modelBuilder.Entity<PasswordChangeVerification>()
                .HasOne(pcv => pcv.User)
                .WithMany()
                .HasForeignKey(pcv => pcv.UserId)
                .IsRequired();

            // UserSession to User (one-to-many)
            modelBuilder.Entity<UserSession>()
                .HasOne(us => us.User)
                .WithMany()
                .HasForeignKey(us => us.UserId)
                .IsRequired();

            // Unique constraints
            modelBuilder.Entity<User>()
                .HasIndex(u => u.Username)
                .IsUnique();

            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique();

            // Unique constraint for Permission Name
            modelBuilder.Entity<Permission>()
                .HasIndex(p => p.Name)
                .IsUnique();


            // Follow entity configuration
            modelBuilder.Entity<Follow>()
                .HasKey(f => new { f.FollowerId, f.FolloweeId });

            modelBuilder.Entity<Follow>()
                .HasOne(f => f.FollowerUser)
                .WithMany(u => u.Following)
                .HasForeignKey(f => f.FollowerId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<Follow>()
                .HasOne(f => f.FolloweeUser)
                .WithMany(u => u.FollowersList)
                .HasForeignKey(f => f.FolloweeId)
                .OnDelete(DeleteBehavior.Restrict);

            // UserProfileImage to User (one-to-one)
            modelBuilder.Entity<User>()
                .HasOne<UserProfileImage>()
                .WithOne(upi => upi.User)
                .HasForeignKey<UserProfileImage>(upi => upi.UserId);

            // UserSettings to User (one-to-one)
            modelBuilder.Entity<UserSettings>()
                .HasOne(us => us.User) // UserSettings has one User
                .WithOne(u => u.Settings) // User has one UserSettings (navigation property in User)
                .HasForeignKey<UserSettings>(us => us.UserId); // The FK is UserSettings.UserId
        }
    }
}

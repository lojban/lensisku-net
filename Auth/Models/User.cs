using System.ComponentModel.DataAnnotations.Schema;
using System.Collections.Generic; // Required for ICollection

namespace Lensisku.Auth.Models;

[Table("users")]
public class User
{
    [Column("userid")]
    public int UserId { get; set; }
    
    [Column("username")]
    public required string Username { get; set; }
    
    [Column("email")]
    public required string Email { get; set; }
    
    [Column("password")]
    public required string PasswordHash { get; set; }
    
    [Column("role")]
    public UserRole Role { get; set; } // This is the enum UserRole
    
    [Column("created_at")]
    public DateTime CreatedAt { get; set; }
    
    [Column("followers")]
    public int Followers { get; set; }
    
    [Column("email_confirmed")]
    public bool EmailConfirmed { get; set; }
    
    [Column("email_confirmation_token")]
    public string? EmailConfirmationToken { get; set; }
    
    [Column("email_confirmation_sent_at")]
    public DateTime? EmailConfirmationSentAt { get; set; }

    [Column("realname")]
    public string? RealName { get; set; }

    [Column("url")]
    public string? Url { get; set; }

    [Column("personal")]
    public string? Personal { get; set; }

    [Column("votesize")] 
    public float? VoteSize { get; set; } // PostgreSQL 'real' maps to C# 'float', made nullable

    [Column("subscription_status")]
    public required string SubscriptionStatus { get; set; } // Mapped as string. Consider creating/using a C# UserSubscriptionStatus enum if 'user_subscription_status' is a PostgreSQL enum.

    [Column("paypal_customer_id")]
    public string? PaypalCustomerId { get; set; }

    [Column("oauth_signup")]
    public bool? OAuthSignup { get; set; } // Made nullable

    [Column("disabled_at")]
    public DateTime? DisabledAt { get; set; }

    [Column("disabled_by")]
    public int? DisabledByUserId { get; set; }

    public virtual UserSettings Settings { get; set; } = new UserSettings();
    [Column("disabled")]
    public bool Disabled { get; set; }
    public virtual ICollection<Follow> Following { get; set; } = new List<Follow>();
    public virtual ICollection<Follow> FollowersList { get; set; } = new List<Follow>();
}
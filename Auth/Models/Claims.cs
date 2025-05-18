using System;
using System.Collections.Generic;

namespace Lensisku.Auth.Models;

public class Claims
{
    public int Sub { get; set; } // UserId
    public long Exp { get; set; } // Expiration timestamp
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public UserRole Role { get; set; }
    public bool EmailConfirmed { get; set; }
    public List<string> Authorities { get; set; } = new();
    public Guid? Sid { get; set; } // Nullable Session ID
}
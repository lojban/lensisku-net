namespace Lensisku.Auth.Services
{
    // IPasswordHasherService defines the contract for password hashing and verification.
    // Using an interface allows for different hashing algorithms or implementations to be used.
    public interface IPasswordHasherService
    {
        // Hashes a plain-text password.
        string HashPassword(string password);
        // Verifies a plain-text password against a stored hash.
        bool VerifyPassword(string password, string storedHash);
        // Checks if a stored hash needs to be rehashed (e.g., if it uses an outdated algorithm or work factor).
        bool NeedsRehash(string storedHash);
    }
}

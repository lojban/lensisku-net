using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Lensisku.Auth.Services
{
    // PasswordHasherService implements IPasswordHasherService and provides password hashing and verification logic.
    // It supports BCrypt for modern hashing and includes logic for handling legacy MD5 hashes.
    public class PasswordHasherService : IPasswordHasherService
    {
        // BCrypt work factor determines the computational cost of hashing. Higher values are more secure but slower.
        private const int BCryptWorkFactor = 12; // Default cost in Rust was DEFAULT_COST (usually 12)

        // Hashes a plain-text password using BCrypt.
        public string HashPassword(string password)
        {
            // Always use bcrypt for new passwords
            return BCrypt.Net.BCrypt.HashPassword(password, BCryptWorkFactor);
        }

        // Verifies a plain-text password against a stored hash.
        // It checks if the hash is legacy (MD5) or modern (BCrypt) and uses the appropriate verification method.
        public bool VerifyPassword(string password, string storedHash)
        {
            if (string.IsNullOrEmpty(storedHash))
            {
                return false;
            }

            // This try-catch block handles potential exceptions during hash verification,
            // especially if the stored hash is malformed or not a valid BCrypt hash.
            try
            {
                if (NeedsRehash(storedHash))
                {
                    // MD5 hash (with ROT13)
                    string rot13Password = Rot13(password);
                    using (MD5 md5 = MD5.Create())
                    // This block handles verification for legacy MD5 hashes, which also involved ROT13 obfuscation.
                    {
                        byte[] inputBytes = Encoding.UTF8.GetBytes(rot13Password);
                        byte[] hashBytes = md5.ComputeHash(inputBytes);
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < hashBytes.Length; i++)
                        {
                            sb.Append(hashBytes[i].ToString("x2"));
                        }
                        return sb.ToString() == storedHash;
                    }
                }
                else if (storedHash.StartsWith("$2a$") || storedHash.StartsWith("$2b$") || storedHash.StartsWith("$2y$"))
                {
                    // Standard BCrypt hashes start with these prefixes.
                    // bcrypt hash
                    return BCrypt.Net.BCrypt.Verify(password, storedHash);
                }
            }
            catch (BCrypt.Net.SaltParseException)
            {
                // Handle cases where the hash is not a valid bcrypt hash, possibly legacy or corrupted
                return false;
            }
            catch (Exception)
            {
                // General exception during verification
                return false;
            }
            
            // If hash format is unknown or verification failed through known methods
            return false;
        }

        // Determines if a stored hash needs to be rehashed to a more secure format (BCrypt).
        // This is typically true for legacy MD5 hashes.
        public bool NeedsRehash(string storedHash)
        {
            // MD5 hash is 32 hex characters and doesn't start with bcrypt prefixes
            return storedHash.Length == 32 && storedHash.All(c => Uri.IsHexDigit(c)) &&
                   !storedHash.StartsWith("$2"); // Basic check, bcrypt hashes start with $2a$, $2b$, $2y$
        }

        // ROT13 is a simple letter substitution cipher. Its use here is part of a legacy password handling scheme.
        private string Rot13(string input)
        {
            return new string(input.Select(c =>
            {
                if (c >= 'a' && c <= 'm' || c >= 'A' && c <= 'M')
                    return (char)(c + 13);
                if (c >= 'n' && c <= 'z' || c >= 'N' && c <= 'Z')
                    return (char)(c - 13);
                return c;
            }).ToArray());
        }
    }
}
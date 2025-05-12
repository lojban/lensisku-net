using Lensisku.Auth.Models;
using System;
using System.Threading.Tasks;

namespace Lensisku.Auth.Services
{
    // Interfaces define a contract for a class. They specify what a class *can do* without dictating *how* it does it.
    // This promotes loose coupling, allowing different implementations to be swapped out (e.g., for testing or different data stores).
    // IUserSessionService defines the operations related to managing user sessions.
    public interface IUserSessionService
    {
        // Asynchronous method to start a new user session. Returns a Task<UserSession?>,
        // indicating it's an async operation that will eventually yield a UserSession object or null.
        Task<UserSession?> StartSessionAsync(int userId, string ipAddress, string? userAgent);
        // Updates the last activity time and potentially IP/UserAgent for an existing session.
        Task<UserSession?> UpdateSessionActivityAsync(int userId, long sessionId, string ipAddress, string? userAgent); // sessionId is PK from DB
        // Retrieves a session by its unique UUID.
        Task<UserSession?> GetSessionByUuidAsync(Guid sessionUuid);
        // Retrieves the database primary key (Id) of a session given its UUID.
        Task<long?> GetSessionIdFromUuidAsync(Guid sessionUuid); // To get DB PK from UUID
        // Ends a specific user session identified by its UUID.
        Task<bool> EndSessionAsync(int userId, Guid? sessionUuid); // End specific session by UUID
        // Ends the current active session for a user, typically the most recent one if not specified by UUID.
        Task<bool> EndUserActiveSessionAsync(int userId); // Ends the current active session for a user if not specified by UUID
    }
}

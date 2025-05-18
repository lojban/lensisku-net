using Lensisku.Auth.Models;
using Lensisku.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Lensisku.Auth.Services
{
    // UserSessionService implements IUserSessionService and provides logic for managing user login sessions.
    // This includes starting, updating, retrieving, and ending sessions.
    public class UserSessionService : IUserSessionService
    {
        private readonly AppDbContext _context;
        private readonly ILogger<UserSessionService> _logger;

        // Constructor for dependency injection.
        public UserSessionService(AppDbContext context, ILogger<UserSessionService> logger)
        {
            _context = context;
            _logger = logger;
        }

        // Starts a new user session and saves it to the database.
        public async Task<UserSession?> StartSessionAsync(int userId, string ipAddress, string? userAgent)
        {
            var session = new UserSession
            {
                UserId = userId,
                SessionUuid = Guid.NewGuid(),
                IpAddress = ipAddress,
                UserAgent = userAgent,
                StartedAt = DateTime.UtcNow,
                LastActivityAt = DateTime.UtcNow
                // SessionUuid is a GUID, providing a unique identifier for the session that can be used in tokens.
            };

            try
            {
                _context.UserSessions.Add(session);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Started session {SessionUuid} for user {UserId}", session.SessionUuid, userId);
                return session;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting session for user {UserId}", userId);
                return null;
            }
        }

        // Updates the activity timestamp and potentially IP/UserAgent of an existing, active session.
        public async Task<UserSession?> UpdateSessionActivityAsync(int userId, long sessionId, string ipAddress, string? userAgent)
        {
            try
            {
                // Finds an active session (EndedAt == null) matching the provided IDs.
                var session = await _context.UserSessions
                    .FirstOrDefaultAsync(s => s.Id == sessionId && s.UserId == userId && s.EndedAt == null);


                if (session != null)
                {
                    session.LastActivityAt = DateTime.UtcNow;
                    session.IpAddress = ipAddress; // Update IP on activity
                    session.UserAgent = userAgent; // Update User Agent on activity
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Updated activity for session {SessionId} (UUID: {SessionUuid}) for user {UserId}", session.Id, session.SessionUuid, userId);
                    return session;
                }
                _logger.LogWarning("Attempted to update activity for non-existent or ended session ID {SessionId} for user {UserId}", sessionId, userId);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating session activity for session ID {SessionId}, user {UserId}", sessionId, userId);
                return null;
            }
        }
        
        // Retrieves an active session by its UUID.
        public async Task<UserSession?> GetSessionByUuidAsync(Guid sessionUuid)
        {
             try
            // Looks for a session that matches the UUID and has not ended.
            {
                return await _context.UserSessions
                    .FirstOrDefaultAsync(s => s.SessionUuid == sessionUuid && s.EndedAt == null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving session by UUID {SessionUuid}", sessionUuid);
                return null;
            }
        }

        // Retrieves the database primary key (Id) of an active session given its UUID.
        public async Task<long?> GetSessionIdFromUuidAsync(Guid sessionUuid)
        {
            try
            {
                // Selects only the Id field, which can be more efficient if the full entity isn't needed.
                var session = await _context.UserSessions
                    .Where(s => s.SessionUuid == sessionUuid && s.EndedAt == null)
                    .Select(s => (long?)s.Id) // Cast to nullable long
                    .FirstOrDefaultAsync();
                return session;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving session ID from UUID {SessionUuid}", sessionUuid);
                return null;
            }
        }

        // Ends a specific user session by marking its EndedAt timestamp.
        public async Task<bool> EndSessionAsync(int userId, Guid? sessionUuid)
        {
            if (!sessionUuid.HasValue) return false;

            try
            {
                // Finds the specified active session for the user.
                var session = await _context.UserSessions
                    .FirstOrDefaultAsync(s => s.UserId == userId && s.SessionUuid == sessionUuid.Value && s.EndedAt == null);

                if (session != null)
                {
                    session.EndedAt = DateTime.UtcNow;
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Ended session {SessionUuid} for user {UserId}", session.SessionUuid, userId);
                    return true;
                }
                _logger.LogWarning("Attempted to end non-existent or already ended session {SessionUuid} for user {UserId}", sessionUuid.Value, userId);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error ending session {SessionUuid} for user {UserId}", sessionUuid.Value, userId);
                return false;
            }
        }

        // Ends the most recent active session for a user if no specific session UUID is provided.
        public async Task<bool> EndUserActiveSessionAsync(int userId)
        {
            // This method might need more specific logic if a user can have multiple active sessions.
            // Assuming for now a user has at most one "current" active session identifiable for logout.
            // If using JWT sid, that would be the one to target.
            // For a general "logout all" or "logout current based on some criteria", this needs refinement.
            // The Rust service `end_session` takes `user_id` only, implying it ends the most recent/current.
            // Let's find the most recent, non-ended session.
            try
            {
                // Finds the user's active session, ordered by last activity (or start time) to get the most recent.
                var activeSession = await _context.UserSessions
                    .Where(s => s.UserId == userId && s.EndedAt == null)
                    .OrderByDescending(s => s.LastActivityAt ?? s.StartedAt)
                    .FirstOrDefaultAsync();

                if (activeSession != null)
                {
                    activeSession.EndedAt = DateTime.UtcNow;
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Ended active session {SessionUuid} for user {UserId} (generic logout)", activeSession.SessionUuid, userId);
                    return true;
                }
                _logger.LogInformation("No active session found to end for user {UserId} (generic logout)", userId);
                return false; // No active session found to end
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error ending active session for user {UserId}", userId);
                return false;
            }
        }
    }
}
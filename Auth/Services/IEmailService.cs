using System.Threading.Tasks;

namespace Lensisku.Auth.Services
{
    // EmailNotificationDto is a Data Transfer Object used to carry information needed to send an email.
    public class EmailNotificationDto
    {
        public string ToEmail { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public string TextBody { get; set; } = string.Empty;
        public string HtmlBody { get; set; } = string.Empty;
        // Includes recipient, subject, and both plain text and HTML versions of the email body.
    }

    // IEmailService defines the contract for email sending operations.
    public interface IEmailService
    {
        // Asynchronously sends an email based on the provided EmailNotificationDto.
        Task SendEmailAsync(EmailNotificationDto emailNotification);
        // Helper to build content, similar to Rust's build_email_content
        // A utility method to construct standardized email content (both text and HTML).
        // Takes an array of message lines and an optional call-to-action link.
        (string textBody, string htmlBody) BuildEmailContent(string[] messageContent, (string linkText, string url)? callToActionLink);
    }
}

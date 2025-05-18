using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using System;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Lensisku.Auth.Services
{
    // EmailService implements IEmailService and is responsible for constructing and sending emails.
    // It uses SMTP (Simple Mail Transfer Protocol) for email delivery.
    public class EmailService : IEmailService
    {
        private readonly ILogger<EmailService> _logger;
        // Configuration settings for email construction and SMTP.
        private readonly string _frontendUrl;
        private readonly string? _smtpHost;
        private readonly int _smtpPort;
        // SMTP credentials are often required for authenticated SMTP relay.

        private readonly string? _smtpUsername;
        private readonly string? _smtpPassword;
        private readonly string? _smtpFromAddress;

        public EmailService(ILogger<EmailService> logger, IConfiguration configuration)
        {
            _logger = logger;
            // Loads configuration values from IConfiguration (e.g., appsettings.json, environment variables).
            _frontendUrl = configuration["FRONTEND_URL"] ?? Environment.GetEnvironmentVariable("FRONTEND_URL") ?? "http://localhost:8080"; // Default fallback

            _smtpHost = configuration["SMTP_HOST"] ?? Environment.GetEnvironmentVariable("SMTP_HOST");
            _smtpPort = int.TryParse(configuration["SMTP_PORT"] ?? Environment.GetEnvironmentVariable("SMTP_PORT"), out var port) ? port : 25; // Default to 25 if not found or invalid
            _smtpUsername = configuration["SMTP_USERNAME"] ?? Environment.GetEnvironmentVariable("SMTP_USERNAME");
            _smtpPassword = configuration["SMTP_PASSWORD"] ?? Environment.GetEnvironmentVariable("SMTP_PASSWORD");
            _smtpFromAddress = configuration["SMTP_FROM_ADDRESS"] ?? Environment.GetEnvironmentVariable("SMTP_FROM_ADDRESS");

            if (string.IsNullOrEmpty(_smtpHost) || string.IsNullOrEmpty(_smtpFromAddress))
            {
                _logger.LogWarning("SMTP Host or From Address is not configured. Email sending might fail.");
            }
        }

        // Builds the text and HTML content for an email.
        // 'messageContent' is an array of strings forming the main body.
        // 'callToActionLink' is an optional tuple for creating a clickable link (e.g., for confirmation or password reset).
        public (string textBody, string htmlBody) BuildEmailContent(string[] messageContent, (string linkText, string url)? callToActionLink)
        {
            var textBuilder = new StringBuilder();
            var htmlBuilder = new StringBuilder(); // StringBuilders are efficient for concatenating multiple strings.

            htmlBuilder.AppendLine("<p>");
            foreach (var line in messageContent)
            {
                textBuilder.AppendLine(line);
                htmlBuilder.AppendLine(System.Net.WebUtility.HtmlEncode(line) + "<br/>");
            }
            htmlBuilder.AppendLine("</p>");

            if (callToActionLink.HasValue)
            {
                var (linkText, url) = callToActionLink.Value;
                // Constructs the full URL, ensuring it's absolute.
                string fullUrl = url.StartsWith("http") ? url : $"{_frontendUrl.TrimEnd('/')}/{url.TrimStart('/')}";
                
                textBuilder.AppendLine();
                textBuilder.AppendLine($"{linkText}: {fullUrl}");

                htmlBuilder.AppendLine($"<p><a href=\"{HttpUtility.HtmlAttributeEncode(fullUrl)}\">{System.Net.WebUtility.HtmlEncode(linkText)}</a></p>");
            }
            
            // Basic HTML structure
            // Creates a simple HTML wrapper for the email content.
            string finalHtml = $@"
<html>
<body>
{htmlBuilder.ToString()}
<hr/>
<p><small>If you did not request this email, please ignore it.</small></p>
<p><small>This is an automated message from Lensisku.</small></p>
</body>
</html>";

            return (textBuilder.ToString(), finalHtml);
        }

        // Sends an email using the configured SMTP settings.
        public async Task SendEmailAsync(EmailNotificationDto emailNotification)
        {
            _logger.LogInformation("---- Attempting to Send Email ----");
            _logger.LogInformation("To: {ToEmail}", emailNotification.ToEmail);
            _logger.LogInformation("Subject: {Subject}", emailNotification.Subject);

            if (string.IsNullOrEmpty(_smtpHost) || string.IsNullOrEmpty(_smtpFromAddress))
            // If SMTP settings are missing, logs a warning and skips sending.
            {
                _logger.LogError("SMTP settings (Host or From Address) are not configured. Cannot send email.");
                _logger.LogInformation("---- Email Sending Skipped (Configuration Missing) ----");
                // Log the email content if SMTP is not configured, similar to previous behavior
                _logger.LogInformation("---- Text Body (Not Sent) ----\n{TextBody}", emailNotification.TextBody);
                _logger.LogInformation("---- HTML Body (Not Sent) ----\n{HtmlBody}", emailNotification.HtmlBody);
                return; // Or throw an exception, depending on desired behavior
            }

            try
            {
                // SmtpClient is used to send emails via an SMTP server.
                using (var client = new SmtpClient(_smtpHost, _smtpPort))
                {
                    if (!string.IsNullOrEmpty(_smtpUsername))
                    {
                        // Sets credentials if SMTP server requires authentication.
                        client.Credentials = new NetworkCredential(_smtpUsername, _smtpPassword);
                    }
                    // client.EnableSsl = true; // Enable SSL if your SMTP server requires it. Often port 587 uses STARTTLS (EnableSsl=true), port 465 uses implicit SSL.
                                            // For port 25, SSL is often not used by default, or STARTTLS might be an option.
                                            // This might need to be configurable or determined based on the port.
                                            // For now, let's assume it might be needed for non-standard ports or secure connections.
                    if (_smtpPort == 587 || _smtpPort == 465) // Common ports for SSL/TLS
                    // Enables SSL/TLS encryption if using standard secure SMTP ports.
                    {
                        client.EnableSsl = true;
                    }


                    // MailMessage represents an email message that can be sent using SmtpClient.
                    using (var mailMessage = new MailMessage())
                    {
                        mailMessage.From = new MailAddress(_smtpFromAddress, "Lensisku");
                        mailMessage.To.Add(emailNotification.ToEmail);
                        mailMessage.Subject = emailNotification.Subject;
                        mailMessage.Body = emailNotification.HtmlBody; // Send HTML body
                        mailMessage.IsBodyHtml = true;

                        // Optionally, add plain text version
                        // var plainTextView = AlternateView.CreateAlternateViewFromString(emailNotification.TextBody, null, "text/plain");
                        // mailMessage.AlternateViews.Add(plainTextView);

                        // Asynchronously sends the email.
                        await client.SendMailAsync(mailMessage);
                        _logger.LogInformation("Email sent successfully to {ToEmail}", emailNotification.ToEmail);
                    }
                }
            }
            // Catches exceptions specific to SMTP operations.
            catch (SmtpException smtpEx)
            {
                _logger.LogError(smtpEx, "SMTP error occurred while sending email to {ToEmail}. Status Code: {StatusCode}", emailNotification.ToEmail, smtpEx.StatusCode);
                // Log detailed body content if sending failed for debugging
                _logger.LogInformation("---- Failed Email Details ----");
                _logger.LogInformation("---- Text Body ----\n{TextBody}", emailNotification.TextBody);
                _logger.LogInformation("---- HTML Body ----\n{HtmlBody}", emailNotification.HtmlBody);

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred while sending email to {ToEmail}", emailNotification.ToEmail);
                // Log detailed body content if sending failed for debugging
                _logger.LogInformation("---- Failed Email Details ----");
                _logger.LogInformation("---- Text Body ----\n{TextBody}", emailNotification.TextBody);
                _logger.LogInformation("---- HTML Body ----\n{HtmlBody}", emailNotification.HtmlBody);
            }
            _logger.LogInformation("---- Email Sending Process Completed ----");
        }
    }
}

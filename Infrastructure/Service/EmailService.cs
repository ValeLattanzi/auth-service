using JWTAuthService.Errors;
using JWTAuthService.Infrastructure.Repository;
using JWTAuthService.Infrastructure.Requests;
using JWTAuthService.Shared.Configuration;
using MailKit.Security;
using Microsoft.Extensions.Configuration;
using MimeKit;
using result_pattern;

namespace JWTAuthService.Infrastructure.Service;

public sealed class EmailService : IEmailRepository
{
	public async Task<Result<bool>> SendEmail(SmptConfiguration smptConfiguration, SendEmailRequest request, string appName, bool isHtml = true)
	{

		// 1. Validate parameters
		if (smptConfiguration == null) return Result.failure<bool>(EmailErrors.SmptConfigurationNotProvided);
		if (request is null) return Result.failure<bool>(EmailErrors.SendEmailRequestNotProvided);


		try
		{
			// * Create a new email message
			var message = new MimeMessage();

			// * Add the sender
			message.From.Add(new MailboxAddress(appName, smptConfiguration.UserName));
			// * Add the recipient
			message.To.Add(new MailboxAddress(request.To, request.To));
			// * Add the subject
			message.Subject = request.Subject;
			// * Add the body
			message.Body = new TextPart(isHtml ? "html" : "plain")
			{
				Text = request.Body
			};

			// * Create a new SMTP client
			using (var client = new MailKit.Net.Smtp.SmtpClient())
			{
				// * Connect to the SMTP server
				await client.ConnectAsync(smptConfiguration.Host, smptConfiguration.Port, SecureSocketOptions.StartTls);
				// * Authenticate with the SMTP server
				await client.AuthenticateAsync(smptConfiguration.UserName, smptConfiguration.Password);
				// * Send the email
				await client.SendAsync(message);
				// * Disconnect from the SMTP server
				await client.DisconnectAsync(true);
			}

			return Result.success(true);
		}
		catch (Exception ex)
		{
			return Result<bool>.failure(EmailErrors.FailOnSend(ex.Message));
		}
	}
}
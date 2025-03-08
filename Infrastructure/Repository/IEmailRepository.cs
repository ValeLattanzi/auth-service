using JWTAuthService.Infrastructure.Data;
using MailKit.Net.Smtp;
using result_pattern;

namespace JWTAuthService.Infrastructure.Repository;

public interface IEmailRepository
{
	Task<Result<bool>> SendEmail(SmptConfiguration smptConfiguration, SendEmailRequest request, string appName, bool isHtml = true);
}
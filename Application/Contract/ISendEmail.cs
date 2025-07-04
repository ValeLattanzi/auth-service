using JWTAuthService.Infrastructure.Data;

namespace JWTAuthService.Application.Contract;

public interface ISendEmail
{
  Task<bool> Notificate(SmptConfiguration smptConfiguration, SendEmailRequest request, string appName, bool isHtml = true);
}

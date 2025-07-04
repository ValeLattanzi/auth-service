using JWTAuthService.Infrastructure.Requests;
using JWTAuthService.Shared.Configuration;

namespace JWTAuthService.Application.Contract;

public interface ISendEmail
{
  Task<bool> Notificate(SmptConfiguration smptConfiguration, SendEmailRequest request, string appName, bool isHtml = true);
}

using JWTAuthService.Application.Contract;
using JWTAuthService.Infrastructure.Requests;
using JWTAuthService.Infrastructure.Service;
using JWTAuthService.Shared.Configuration;

namespace JWTAuthService.Application.UseCase;

public class SendEmail : ISendEmail
{
  private readonly EmailService _emailService;

  public SendEmail(EmailService emailService)
  {
    _emailService = emailService;
  }

  public async Task<bool> Notificate(SmptConfiguration smptConfiguration, SendEmailRequest request, string appName, bool isHtml = true)
  {
    try
    {
      await _emailService.SendEmail(smptConfiguration, request, appName, isHtml);
      return true;
    }
    catch (Exception e)
    {
      Console.WriteLine(e);
      return false;
    }
  }
}
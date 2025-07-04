using System.Text.Encodings.Web;
using JWTAuthService.Application.Contract;
using JWTAuthService.Infrastructure.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JWTAuthService.Infrastructure.MiddleWare;

public class AuthCookieHandler : AuthenticationHandler<AuthenticationSchemeOptions> {
  private const string ACCESS_COOKIE = "access-token";
  private const string AUTH_SCHEME = "Bearer";
  private readonly IConfiguration _configuration;
  private readonly ITokenValidator _tokenValidator;

  public AuthCookieHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ISystemClock clock,
    IConfiguration configuration,
    ITokenValidator tokenValidator)
    : base(options, logger, encoder, clock) {
    _configuration = configuration;
    _tokenValidator = tokenValidator;
  }

  protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
    if (!Request.Cookies.ContainsKey(ACCESS_COOKIE))
      return AuthenticateResult.Fail("Access token not found");

    var jwtAccessToken = Request.Cookies[ACCESS_COOKIE];

    var accessKey = _configuration["Jwt:AccessKey"]!;

    var accessResult = _tokenValidator.ValidateToken(jwtAccessToken, accessKey, Scheme.Name);
    if (accessResult.Succeeded)
      return accessResult;

    return AuthenticateResult.Fail("Failed to authenticate with new access token");
  }
}
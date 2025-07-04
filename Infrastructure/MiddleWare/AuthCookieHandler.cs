using System.Text.Encodings.Web;
using JWTAuthService.Application.Contract;
using JWTAuthService.Infrastructure.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JWTAuthService.Infrastructure.MiddleWare;

public  class AuthCookieHandler : AuthenticationHandler<AuthenticationSchemeOptions> {
private readonly IConfiguration _configuration;
    private readonly IRefreshAccessToken _refreshAccessToken;
    private readonly ITokenValidator _tokenValidator;

    private const string ACCESS_COOKIE = "access-token";
    private const string REFRESH_COOKIE = "refresh-token";
    private const string AUTH_SCHEME = "Bearer";

    public AuthCookieHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        IConfiguration configuration,
        IRefreshAccessToken refreshAccessToken,
        ITokenValidator tokenValidator)
        : base(options, logger, encoder, clock)
    {
        _configuration = configuration;
        _refreshAccessToken = refreshAccessToken;
        _tokenValidator = tokenValidator;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.ContainsKey(ACCESS_COOKIE))
            return AuthenticateResult.Fail("Access token not found");

        var jwtAccessToken = Request.Cookies[ACCESS_COOKIE];
        var jwtRefreshToken = Request.Cookies.ContainsKey(REFRESH_COOKIE)
                                ? Request.Cookies[REFRESH_COOKIE]
                                : null;

        var accessKey = _configuration["Jwt:AccessKey"]!;
        var refreshKey = _configuration["Jwt:RefreshKey"]!;

        var accessResult = _tokenValidator.ValidateToken(jwtAccessToken, accessKey, Scheme.Name);
        if (accessResult.Succeeded)
            return accessResult;

        // Si el access token falla y no hay refresh, error
        if (string.IsNullOrWhiteSpace(jwtRefreshToken))
            return AuthenticateResult.Fail("Access token expired and no refresh token provided");

        var refreshResult = _tokenValidator.ValidateToken(jwtRefreshToken, refreshKey, Scheme.Name);
        if (!refreshResult.Succeeded)
            return AuthenticateResult.Fail("Refresh token invalid or expired");

        var claims = _tokenValidator.GetClaims(jwtRefreshToken, refreshKey);

        var newAccessToken = _refreshAccessToken.Refresh(claims, accessKey);
        if (string.IsNullOrWhiteSpace(newAccessToken))
            return AuthenticateResult.Fail("Failed to refresh access token");

        var newAccessResult = _tokenValidator.ValidateToken(newAccessToken, accessKey, Scheme.Name);
        if (newAccessResult.Succeeded)
        {
            Response.Cookies.Append(ACCESS_COOKIE, newAccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddMinutes(15)
            });
            return newAccessResult;
        }

        return AuthenticateResult.Fail("Failed to authenticate with new access token");
    }
}
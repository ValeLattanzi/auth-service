using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using JWTAuthService.Application.Contract;

namespace JWTAuthService.Infrastructure.MiddleWare;

public class JWTAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IConfiguration _configuration;
    private readonly IRefreshAccessToken _refreshAccessToken;

    private const string AUTH_HEADER = "Authorization";
    private const string REFRESH_HEADER = "Refresh-Token";
    private const string ACCESS_KEY = "Jwt:AccessKey";
    private const string REFRESH_KEY = "Jwt:RefreshKey";
    private const string AUTH_SCHEME = "Bearer";

    [Obsolete]
    public JWTAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
                            ILoggerFactory logger,
                            UrlEncoder encoder,
                            ISystemClock clock,
                            IConfiguration configuration,
                            IRefreshAccessToken refreshToken)
        : base(options, logger, encoder, clock)
    {
        _configuration = configuration;
        _refreshAccessToken = refreshToken;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.ContainsKey(AUTH_HEADER) || !Request.Headers.ContainsKey(REFRESH_HEADER))
            return AuthenticateResult.Fail("Unauthorized");

        string? _accessToken = Request.Headers[AUTH_HEADER];
        string? _refreshToken = Request.Headers[REFRESH_HEADER];

        if (string.IsNullOrWhiteSpace(_accessToken) ||
            !_accessToken.StartsWith(AUTH_SCHEME) ||
            string.IsNullOrWhiteSpace(_refreshToken) ||
            !_refreshToken.StartsWith(AUTH_SCHEME))
            return AuthenticateResult.Fail("Invalid token");

        string jwtAccessToken = _accessToken[$"{AUTH_SCHEME} ".Length..].Trim();
        string jwtRefreshToken = _refreshToken[$"{AUTH_SCHEME} ".Length..].Trim();

        var _tokenHandler = new JwtSecurityTokenHandler();
        // Toma la clave para cifrar el access token
        var _accessKey = Encoding.ASCII.GetBytes(_configuration[ACCESS_KEY]!);

        // Valida el access token
        var _accessResult = ValidateToken(jwtAccessToken, _tokenHandler, _accessKey);
        // Clausula de guarda en caso de que el token sea correcto
        if (_accessResult.Succeeded)
            return _accessResult;

        // Toma la clave para cifrar el refresh token
        var _refreshKey = Encoding.ASCII.GetBytes(_configuration[REFRESH_KEY]!);
        var _refreshResult = ValidateToken(jwtRefreshToken, _tokenHandler, _refreshKey);

        // Si el refresh token expira
        if (!_refreshResult.Succeeded)
            return AuthenticateResult.Fail("Token was expired");

        var _claims = GetClaimsFromToken(jwtRefreshToken, _tokenHandler, _refreshKey);

        var _newAccessToken = _refreshAccessToken.Refresh(_claims, _configuration[ACCESS_KEY]!);

        if (string.IsNullOrWhiteSpace(_newAccessToken))
            return AuthenticateResult.Fail("Failed to refresh token");

        _accessResult = ValidateToken(_newAccessToken, _tokenHandler, _accessKey);
        if (_accessResult.Succeeded)
        {
            Response.Headers[AUTH_HEADER] = $"{AUTH_SCHEME} {_newAccessToken}";
            return _accessResult;
        }

        return AuthenticateResult.Fail("Invalid access token");
    }

    private AuthenticateResult ValidateToken(string jwtToken, JwtSecurityTokenHandler tokenHandler, byte[] key)
    {
        try
        {
            tokenHandler.ValidateToken(jwtToken, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero,
                RequireExpirationTime = true
            }, out SecurityToken validatedToken);

            var jwtSecurityToken = (JwtSecurityToken)validatedToken;


            List<Claim> _claims = [];
            foreach (var claim in jwtSecurityToken.Claims) { _claims.Add(claim); }

            var identity = new ClaimsIdentity(_claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            return AuthenticateResult.Fail("Failed to authenticate: " + ex.Message);
        }
    }

    private List<Claim> GetClaimsFromToken(string jwtToken, JwtSecurityTokenHandler tokenHandler, byte[] key)
    {
        try
        {
            tokenHandler.ValidateToken(jwtToken, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero,
                RequireExpirationTime = true
            }, out SecurityToken _validatedToken);
            var _jwtSecurityToken = (JwtSecurityToken)_validatedToken;
            return _jwtSecurityToken.Claims.ToList();
        }
        catch (Exception)
        {
            return [];
        }
    }
}
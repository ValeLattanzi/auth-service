using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthService.Infrastructure.MiddleWare;

public class AuthJwtHandler : AuthenticationHandler<AuthenticationSchemeOptions> {
  private const string AUTH_HEADER = "Authorization";
  private const string ACCESS_KEY = "Jwt:AccessKey";
  private const string AUTH_SCHEME = "Bearer";
  private readonly IConfiguration _configuration;

  [Obsolete]
  public AuthJwtHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ISystemClock clock,
    IConfiguration configuration)
    : base(options, logger, encoder, clock) {
    _configuration = configuration;
  }

  protected override Task<AuthenticateResult> HandleAuthenticateAsync() {
    if (!Request.Headers.ContainsKey(AUTH_HEADER))
      return Task.FromResult(AuthenticateResult.Fail("Unauthorized"));

    string? _accessToken = Request.Headers[AUTH_HEADER];

    if (string.IsNullOrWhiteSpace(_accessToken) ||
        !_accessToken.StartsWith(AUTH_SCHEME))
      return Task.FromResult(AuthenticateResult.Fail("Invalid token"));

    var jwtAccessToken = _accessToken[$"{AUTH_SCHEME} ".Length..].Trim();

    var _tokenHandler = new JwtSecurityTokenHandler();
    // Toma la clave para cifrar el access token
    var _accessKey = Encoding.ASCII.GetBytes(_configuration[ACCESS_KEY]!);

    // Valida el access token
    var _accessResult = ValidateToken(jwtAccessToken, _tokenHandler, _accessKey);

    // Clausula de guarda en caso de que el token sea correcto
    if (_accessResult.Succeeded)
      return Task.FromResult(_accessResult);

    return Task.FromResult(AuthenticateResult.Fail("Invalid token"));
  }

  private AuthenticateResult ValidateToken(string jwtToken, JwtSecurityTokenHandler tokenHandler, byte[] key) {
    try {
      tokenHandler.ValidateToken(jwtToken, new() {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false,
        ClockSkew = TimeSpan.Zero,
        RequireExpirationTime = true
      }, out var validatedToken);

      var jwtSecurityToken = (JwtSecurityToken)validatedToken;

      List<Claim> _claims = [];
      foreach (var claim in jwtSecurityToken.Claims) _claims.Add(claim);

      var identity = new ClaimsIdentity(_claims, Scheme.Name);
      var principal = new ClaimsPrincipal(identity);
      var ticket = new AuthenticationTicket(principal, Scheme.Name);

      return AuthenticateResult.Success(ticket);
    }
    catch (Exception ex) {
      return AuthenticateResult.Fail("Invalid Token");
    }
  }
}
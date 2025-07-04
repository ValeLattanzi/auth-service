using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAuthService.Application.Contract;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthService.Application.UseCase;

public class TokenValidator : ITokenValidator {
  public AuthenticateResult ValidateToken(string token, string key, string schemeName)
  {
    var tokenHandler = new JwtSecurityTokenHandler();
    var keyBytes = Encoding.ASCII.GetBytes(key);

    try
    {
      tokenHandler.ValidateToken(token, new TokenValidationParameters
      {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ValidateIssuer = false,
        ValidateAudience = false,
        ClockSkew = TimeSpan.Zero,
        RequireExpirationTime = true
      }, out SecurityToken validatedToken);

      var jwtToken = (JwtSecurityToken)validatedToken;
      var claims = jwtToken.Claims.ToList();
      var identity = new ClaimsIdentity(claims, schemeName);
      var principal = new ClaimsPrincipal(identity);
      var ticket = new AuthenticationTicket(principal, schemeName);

      return AuthenticateResult.Success(ticket);
    }
    catch (Exception ex)
    {
      return AuthenticateResult.Fail("Token invalid: " + ex.Message);
    }
  }

  public List<Claim> GetClaims(string token, string key)
  {
    var tokenHandler = new JwtSecurityTokenHandler();
    var keyBytes = Encoding.ASCII.GetBytes(key);
    try
    {
      tokenHandler.ValidateToken(token, new TokenValidationParameters
      {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ValidateIssuer = false,
        ValidateAudience = false,
        ClockSkew = TimeSpan.Zero,
        RequireExpirationTime = true
      }, out SecurityToken validatedToken);

      return ((JwtSecurityToken)validatedToken).Claims.ToList();
    }
    catch (Exception)
    {
      return [];
    }
  }
}
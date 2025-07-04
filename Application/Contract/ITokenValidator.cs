using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace JWTAuthService.Application.Contract;

public interface ITokenValidator {
  AuthenticateResult ValidateToken(string token, string key, string schemeName);
  List<Claim> GetClaims(string token, string key);
}
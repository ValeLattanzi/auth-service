using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JWTAuthService.Application.Contract;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthService.Application.UseCase;

public sealed class GenerateToken : IGenerateToken {
  public string GenerateAccessToken(List<Claim> claims, string accessKey) {
    return WriteToken(new(), new() {
      Subject = new(claims),
      Expires = DateTime.UtcNow.AddMinutes(15),
      SigningCredentials = new(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(accessKey)),
        SecurityAlgorithms.HmacSha256Signature)
    });
  }

  public string GenerateRefreshToken() {
    var randomNumber = new byte[64];
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(randomNumber);
    return Convert.ToBase64String(randomNumber);
  }

  private static string WriteToken(JwtSecurityTokenHandler tokenHandler, SecurityTokenDescriptor tokenDescriptor) {
    var _token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(_token);
  }
}
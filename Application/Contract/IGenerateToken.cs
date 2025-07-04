using System.Security.Claims;

namespace JWTAuthService.Application.Contract;

public interface IGenerateToken
{
    string GenerateAccessToken(List<Claim> claims, string accessKey);
    string GenerateRefreshToken(List<Claim> claims, string refreshKey);
}

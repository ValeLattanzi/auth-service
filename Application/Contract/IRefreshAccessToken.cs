using System.Security.Claims;

namespace JWTAuthService.Application.Contract;

public interface IRefreshAccessToken
{
    string Refresh(List<Claim> claims, string accessKey);
}

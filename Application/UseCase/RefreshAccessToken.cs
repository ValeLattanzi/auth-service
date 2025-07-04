using System.Security.Claims;
using JWTAuthService.Application.Contract;

namespace JWTAuthService.Application.UseCase;

public class RefreshAccessToken : IRefreshAccessToken
{
    private readonly IGenerateToken _generateToken;

    public RefreshAccessToken(IGenerateToken generateToken)
    {
        _generateToken = generateToken;
    }

    public string Refresh(List<Claim> claims, string accessKey)
    {
        return _generateToken.GenerateAccessToken(claims, accessKey);
    }
}

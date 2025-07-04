using System.Security.Claims;

namespace JWTAuthService.Application.Contract;

public interface IGenerateToken {
    /// <summary>
    ///   Create an access token with the given claims and access key.
    /// </summary>
    /// <param name="claims"></param>
    /// <param name="accessKey"></param>
    /// <returns></returns>
    string GenerateAccessToken(List<Claim> claims, string accessKey);

    /// <summary>
    ///   Create a refresh token.
    /// </summary>
    /// <returns></returns>
    string GenerateRefreshToken();
}
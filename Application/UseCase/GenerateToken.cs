using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAuthService.Application.Contract;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthService.Application.UseCase;

public sealed class GenerateToken : IGenerateToken {

    public string GenerateAccessToken(List<Claim> claims, string accessKey)
    {        // 1.- Generar el AccessToken
        var _tokenHandler = new JwtSecurityTokenHandler();
        // 2.- Obtiene la clave para cifrar el token
        byte[] _key = Encoding.ASCII.GetBytes(accessKey);
        // 3.- Define la configuracion
        var _tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256Signature)
        };

        var _accessToken = WriteToken(_tokenHandler, _tokenDescriptor);

        return _accessToken;
    }

    public string GenerateRefreshToken(List<Claim> claims, string refreshKey)
    {
        var _tokenHandler = new JwtSecurityTokenHandler();
        var _refreshKey = Encoding.ASCII.GetBytes(refreshKey);
        var _tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(20),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_refreshKey), SecurityAlgorithms.HmacSha256Signature)
        };

        var _refreshToken = WriteToken(_tokenHandler, _tokenDescriptor);
        return _refreshToken;
    }

    private static string WriteToken(JwtSecurityTokenHandler tokenHandler, SecurityTokenDescriptor tokenDescriptor)
    {
        var _token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(_token);
    }
}
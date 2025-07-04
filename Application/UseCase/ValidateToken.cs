using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAuthService.Application.Contract;
using JWTAuthService.Errors;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using result_pattern;

namespace JWTAuthService.Application.UseCase;

public class ValidateToken : IValidateToken {
	private readonly IConfiguration _configuration;


	public ValidateToken(IConfiguration configuration) {
		_configuration = configuration;
	}

	public bool IsExpired(string token, string key) {
		try {
			var _key = _configuration[key] ?? throw new("Invalid Key");
			var _encodedKey = Encoding.ASCII.GetBytes(_key);
			var _tokenHandler = new JwtSecurityTokenHandler();
			_tokenHandler.ValidateToken(token, new() {
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new SymmetricSecurityKey(_encodedKey),
				ValidateIssuer = false,
				ValidateAudience = false,
				ClockSkew = TimeSpan.Zero,
				RequireExpirationTime = true
			}, out _);

			return false;
		}
		catch (SecurityTokenExpiredException) {
			return true;
		}
		catch (Exception ex) {
			Console.WriteLine(ex.Message);
			return true;
		}
	}

	public Result ValidateClaims(string token, List<Claim> claimsToValidate) {
		// Validar claims
		var claims = GetClaims(token).ToList();
		if (!claims.Any()) return Result.failure(AuthErrors.InvalidToken);

		// If any of the claims to validate is not present in the token, return invalid token
		if (claimsToValidate.Any(claimToValidate => !claims.Contains(claimToValidate)))
			return Result.failure(AuthErrors.InvalidToken);

		return Result.success();
	}

	private IEnumerable<Claim> GetClaims(string token) {
		var _tokenHandler = new JwtSecurityTokenHandler();
		var _token = _tokenHandler.ReadJwtToken(token);
		return _token.Claims;
	}
}
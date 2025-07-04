using result_pattern;

namespace JWTAuthService.Application.Contract;

public interface IVerifyUser {
	Result VerifyByEmail(string email, string token, string verificationSecret);
}
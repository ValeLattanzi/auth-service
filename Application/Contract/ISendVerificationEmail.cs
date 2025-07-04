
using JWTAuthService.Infrastructure.Data;
using result_pattern;

namespace JWTAuthService.Application.Contract;

public interface ISendVerificationEmail {
	Task<Result> SendEmail(string email, SmptConfiguration SmptConfiguration, string appName, Uri frontEndUrl,
		Uri appLogoUrl);
}
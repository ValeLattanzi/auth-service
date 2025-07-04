using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAuthService.Application.Contract;
using JWTAuthService.Infrastructure.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using result_pattern;

namespace JWTAuthService.Application.UseCase;

public class SendVerificationEmail : ISendVerificationEmail {
	private readonly ISendEmail _sendEmail;
	private readonly IConfiguration _configuration;

	public SendVerificationEmail(ISendEmail sendEmail, IConfiguration configuration) {
		_sendEmail = sendEmail;
		_configuration = configuration;
	}

	public async Task<Result> SendEmail(string email,
		SmptConfiguration smptConfiguration,
		string appName,
		Uri frontEndUrl,
		Uri appLogoUrl) {
		// Define claims for the token
		var claims = new List<Claim>
		{
			new Claim(JwtRegisteredClaimNames.Email, email),
			new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
		};
		// 1. Create token
		var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:MailTokenKey"]!));
		var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

		var token = new JwtSecurityToken(
			claims: claims,
			expires: DateTime.UtcNow.AddMinutes(15),
			signingCredentials: credentials);

		var emailToken = new JwtSecurityTokenHandler().WriteToken(token);

		// 2. Send email
		var emailBody = $@"
      <div
  style=""
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 1rem;
    border: 1px solid #ccc;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    font-family: Arial, sans-serif;
    background-color: black;
    color: white;
  ""
>
  <img
    src={appLogoUrl}
    alt=""appLogo""
    style=""width: 100px; height: 100px; border-radius: 50%; margin: 1rem 0""
  />
  <h1 style=""font-size: 1.5rem; text-transform: uppercase"">
    Verify your email
  </h1>
  <div style=""font-size: 1.1rem; margin: 1rem 0; text-align: center"">
    <p>Click the link below to verify your email</p>
    <a
      href=""{frontEndUrl}/auth/verify-email?token={emailToken}""
      type=""button""
      style=""
        padding: 0.5rem 1rem;
        background-color: #d30000;
        color: white;
        text-decoration: none;
        border: none;
        border-radius: 5px;
        cursor: pointer;
      ""
      >Verify email</a
    >
    <p>If you didn't request this email, you can ignore it</p>
  </div>
</div>
    ";
		var sendEmailRequest = new SendEmailRequest(email, $"{appName} - Email Verification", emailBody);
		await _sendEmail.Notificate(smptConfiguration, sendEmailRequest, appName);
		return Result.success(true);
	}
}
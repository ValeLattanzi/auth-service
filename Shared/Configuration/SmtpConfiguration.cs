namespace JWTAuthService.Infrastructure.Data;

public record class SmptConfiguration(
  string Host,
  int Port,
  string UserName,
  string Password
);
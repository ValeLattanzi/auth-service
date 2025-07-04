namespace JWTAuthService.Shared.Configuration;

public record class SmptConfiguration(
  string Host,
  int Port,
  string UserName,
  string Password
);
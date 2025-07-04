namespace JWTAuthService.Domain;

public class RefreshToken {
  public Guid Id { get; set; }
  public string Token { get; set; } = string.Empty;
  public Guid UserId { get; set; }
  public DateTime CreatedAt { get; set; }
  public DateTime ExpiresAt { get; set; }
  public bool IsActive => DateTime.UtcNow < ExpiresAt;
}
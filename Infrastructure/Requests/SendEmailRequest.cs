using System.ComponentModel.DataAnnotations;

namespace JWTAuthService.Infrastructure.Data;

public sealed record class SendEmailRequest(
  [Required(ErrorMessage = "The 'To' field is required.")]
  [EmailAddress(ErrorMessage = "The 'To' field is not a valid email address.")]
  string? To,
  [Required(ErrorMessage = "The 'Subject' field is required.")]
  string? Subject,
  string? Body = null
);
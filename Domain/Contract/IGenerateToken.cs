﻿using System.Security.Claims;

namespace JWTAuthService.Domain.Contract;

public interface IGenerateToken
{
    string GenerateAccessToken(List<Claim> claims, string accessKey);
    string GenerateRefreshToken(List<Claim> claims, string refreshKey);
    string GenerateVerificationToken(Guid userId, string email);
}

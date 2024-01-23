using JsonWebToken.DTOs;

namespace JsonWebToken.Interfaces
{
    public interface IAuthService
    {
        Task<AuthDto> RegisterAsync(RegisterDto dto);
        Task<AuthDto> Login(LoginDto dto);
        Task<string> AddRoleAsync(AddRoleDto dto);
        Task<AuthDto> GetRefreshTokenAsync(string token);
        Task<bool> RevokeTokenAsync(string token);
    }
}

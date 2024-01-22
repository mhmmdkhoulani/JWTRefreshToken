using JsonWebToken.DTOs;

namespace JsonWebToken.Interfaces
{
    public interface IAuthService
    {
        Task<AuthDto> RegisterAsync(RegisterDto dto);
        Task<AuthDto> GetTokenAsync(LoginDto dto);
        Task<string> AddRoleAsync(AddRoleDto dto);
    }
}

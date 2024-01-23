using JsonWebToken.Constants;
using JsonWebToken.DTOs;
using JsonWebToken.Interfaces;
using JsonWebToken.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;

        public AuthService(UserManager<AppUser> userManger, IOptions<JWT> jwt, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManger;
            _jwt = jwt.Value;
            _roleManager = roleManager;
        }

        public async Task<string> AddRoleAsync(AddRoleDto dto)
        {
            var user = await GetUserByEmailAsync(dto.Email);
            if (user == null) return "User is not found!";

            var role = await _roleManager.RoleExistsAsync(dto.RoleName);
            if (!role) return "Role is not found!";

            var isInRole = await _userManager.IsInRoleAsync(user, dto.RoleName);
            if (isInRole) return "User already assigned to this role";

            var result = await _userManager.AddToRoleAsync(user, dto.RoleName);
            return result.Succeeded ? string.Empty : "Failed to assign role to the user";
        }

        public async Task<AuthDto> Login(LoginDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
                return new AuthDto { Message = "User or password is invalid!", isAuthenticated = false };

            var isCorrectPassword = await _userManager.CheckPasswordAsync(user, dto.Password);
            if (!isCorrectPassword)
                return new AuthDto { Message = "User or password is invalid!", isAuthenticated = false };

            var authDto = await GenerateAuthDtoAsync(user);
            return authDto;
        }

        public async Task<AuthDto> GetRefreshTokenAsync(string token)
        {
            var authDto = new AuthDto();
            var user = await GetUserByRefreshTokenAsync(token);

            if (user == null)
            {
                authDto.isAuthenticated = false;
                authDto.Message = "Invalid Token";
                return authDto;
            }

            var refreshToken = user.RefreshTokens.Single(t => t.Token == token);
            if (!refreshToken.IsActive)
            {
                authDto.isAuthenticated = false;
                authDto.Message = "Inactive Token";
                return authDto;
            }

            await UpdateUserWithNewRefreshTokenAsync(user);

            var jwtToken = await CreateJwtToken(user);
            var roles = await _userManager.GetRolesAsync(user);

            authDto = new AuthDto
            {
                isAuthenticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                Email = user.Email,
                UserName = user.UserName,
                Roles = roles.ToList(),
                RefreshToken = user.RefreshTokens.First(t => t.IsActive).Token,
                RefreshTokenExpiration = user.RefreshTokens.First(t => t.IsActive).ExpiresOn
            };

            return authDto;
        }

        public async Task<AuthDto> RegisterAsync(RegisterDto dto)
        {
            var userByEmail = await _userManager.FindByEmailAsync(dto.Email);
            var userByName = await _userManager.FindByNameAsync(dto.UserName);

            if (userByEmail != null || userByName != null)
                return new AuthDto { Message = "Email or UserName already exists!", isAuthenticated = false };

            var user = new AppUser
            {
                UserName = dto.UserName,
                Email = dto.Email,
                FirstName = dto.FirstName,
                LastName = dto.LastName,
            };

            var result = await _userManager.CreateAsync(user, dto.Password);

            if (!result.Succeeded)
                return new AuthDto { Message = GetErrors(result.Errors), isAuthenticated = false };

            await _userManager.AddToRoleAsync(user, AppUserRoles.User);

            var jwtSecurityToken = await CreateJwtToken(user);

            return new AuthDto
            {
                isAuthenticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Email = user.Email,
                UserName = user.UserName,
                Roles = new List<string>(),
                Message = "User registered successfully",
            };
        }

        public async Task<bool> RevokeTokenAsync(string token)
        {
            var user = await GetUserByRefreshTokenAsync(token);
            if (user == null)
                return false;

            var refreshToken = user.RefreshTokens.Single(t => t.Token == token);
            if (!refreshToken.IsActive)
                return false;

            refreshToken.RevokedOn = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);
            return true;
        }

        private async Task<AppUser> GetUserByEmailAsync(string email)
        {
            return await _userManager.FindByEmailAsync(email);
        }

        private async Task<AuthDto> GenerateAuthDtoAsync(AppUser user)
        {
            var JWTSecureToken = await CreateJwtToken(user);
            var roles = await _userManager.GetRolesAsync(user);

            var authDto = new AuthDto
            {
                Email = user.Email,
                isAuthenticated = true,
                Message = "Token retrieved successfully",
                Token = new JwtSecurityTokenHandler().WriteToken(JWTSecureToken),
                UserName = user.UserName,
                Roles = roles.ToList()
            };

            if (user.RefreshTokens.Any(t => t.IsActive))
            {
                var activeRefreshToken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
                authDto.RefreshToken = activeRefreshToken.Token;
                authDto.RefreshTokenExpiration = activeRefreshToken.ExpiresOn;
            }
            else
            {
                var refreshToken = GenerateRefreshToken();
                authDto.RefreshToken = refreshToken.Token;
                authDto.RefreshTokenExpiration = refreshToken.ExpiresOn;
                user.RefreshTokens.Add(refreshToken);
                await _userManager.UpdateAsync(user);
            }

            return authDto;
        }

        private async Task<AppUser> GetUserByRefreshTokenAsync(string token)
        {
            return await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
        }

        private async Task UpdateUserWithNewRefreshTokenAsync(AppUser user)
        {
            var refreshToken = GenerateRefreshToken();
            user.RefreshTokens.Add(refreshToken);
            await _userManager.UpdateAsync(user);
        }

        private async Task<JwtSecurityToken> CreateJwtToken(AppUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = roles.Select(role => new Claim("roles", role));

            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim("uid", user.Id)
        }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }

        private RefreshToken GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var generator = new RNGCryptoServiceProvider();
            generator.GetBytes(randomNumber);
            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                ExpiresOn = DateTime.UtcNow.AddDays(10),
                CreatedOn = DateTime.UtcNow,
            };
        }

        private string GetErrors(IEnumerable<IdentityError> errors)
        {
            var errorMessages = errors.Select(error => error.Description);
            return string.Join(", ", errorMessages);
        }
    }
}

using JsonWebToken.Constants;
using JsonWebToken.DTOs;
using JsonWebToken.Interfaces;
using JsonWebToken.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
            var user = await _userManager.FindByEmailAsync(dto.Email);

            if (user == null) return "User is not found!";

            var role = await _roleManager.RoleExistsAsync(dto.RoleName);

            if (!role) return "role is not found!";

            var isInRole = await _userManager.IsInRoleAsync(user, dto.RoleName);

            if (isInRole) return "user already assigned to this role";

            var result = await _userManager.AddToRoleAsync(user, dto.RoleName);

            if (!result.Succeeded)
                return "something went wrong!, user not assigned to the role";

            return "";

        }

        public async Task<AuthDto> GetTokenAsync(LoginDto dto)
        {
          
            var user = await _userManager.FindByEmailAsync(dto.Email);
            
            if (user == null)
                return new AuthDto { Message = "User or password is invalid!", isAuthenticated = false};

            var isCorrectPassword = await _userManager.CheckPasswordAsync(user, dto.Password);

            if (!isCorrectPassword)
                return new AuthDto { Message = "User or password is invalid!", isAuthenticated = false };

            var JWTSecureToken = await CreateJwtToken(user);
            var roles = await _userManager.GetRolesAsync(user);
            return new AuthDto
            {
                Email = user.Email,
                ExpiresOn = JWTSecureToken.ValidTo,
                isAuthenticated = true,
                Message = "Token retrived successfully",
                Token = new JwtSecurityTokenHandler().WriteToken(JWTSecureToken),
                UserName = user.UserName,
                Roles = (List<string>)roles
            };
        }

        public async Task<AuthDto> RegisterAsync(RegisterDto dto)
        {
            var userByEmail = await _userManager.FindByEmailAsync(dto.Email);
            var userByName = await _userManager.FindByNameAsync(dto.UserName);
            if (userByEmail != null)
                return new AuthDto { Message = "Email is already existed!", isAuthenticated = false};
            
            if (userByName != null)
                 return new AuthDto { Message = "UserName is already existed!", isAuthenticated = false };

            var user = new AppUser
            {
                UserName = dto.UserName,
                Email = dto.Email,
                FirstName = dto.FirstName,
                LastName = dto.LastName,
            };

            var result = await _userManager.CreateAsync(user, dto.Password);

            if(!result.Succeeded)
            {
                var errors = string.Empty; 
                foreach (var error in result.Errors)
                {
                    errors += $"{error.Description},";
                }
                return new AuthDto { Message = errors, isAuthenticated = false };
            }
            await _userManager.AddToRoleAsync(user, AppUserRoles.User);

            var jwtSecurityToken = await CreateJwtToken(user);

            return new AuthDto
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                isAuthenticated = true,
                Message = "User registerd successfully",
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                UserName = user.UserName,
                Roles = new List<string>()
            };
        }


        private async Task<JwtSecurityToken> CreateJwtToken(AppUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

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
                expires: DateTime.Now.AddDays(_jwt.Duration),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
    }
}

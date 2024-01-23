using JsonWebToken.DTOs;
using JsonWebToken.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace JsonWebToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.RegisterAsync(dto);
            if (!result.isAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);

        }

        [HttpPost("Login")]
        public async Task<IActionResult> GetTokenAsync([FromBody] LoginDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.Login(dto);
            if (!result.isAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);

        }

        [HttpPost("AddToRole")]
        public async Task<IActionResult> AddUserToRole([FromBody] AddRoleDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.AddRoleAsync(dto);
            if (!string.IsNullOrWhiteSpace(result))
                return BadRequest(result);

            return Ok();

        }

        [HttpGet("refreshToken")]
        public async Task<IActionResult> GetRefreshTokenAsync([FromBody] TokenRequestDto request)
        {
            var result = await _authService.GetRefreshTokenAsync(request.Token);
            if (!result.isAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);

        }

        [HttpPost("revokeToken")]
        public async Task<IActionResult> RevokeTokenAsync([FromBody] TokenRequestDto request)
        {
            if (string.IsNullOrWhiteSpace(request.Token))
                return BadRequest("Token is required");

            var result = await _authService.RevokeTokenAsync(request.Token);
            if (!result)
                return BadRequest("Token is invalid!");

            return Ok("Token is revoked!");

        }
    }
}

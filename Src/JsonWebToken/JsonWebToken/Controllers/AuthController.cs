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
            if(!ModelState.IsValid)
                return BadRequest(ModelState);
            
            var result = await _authService.RegisterAsync(dto);
            if(!result.isAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);  
            
        }

        [HttpPost("Login")]
        public async Task<IActionResult> GetTokenAsync([FromBody] LoginDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.GetTokenAsync(dto);
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
    }
}

using System.ComponentModel.DataAnnotations;

namespace JsonWebToken.DTOs
{
    public class RegisterDto
    {
        [Required, MaxLength(50)]
        public string FirstName { get; set; } = string.Empty;
        [Required, MaxLength(50)]
        public string LastName { get; set; } = string.Empty;
        [Required, MaxLength(50)]
        public string UserName { get; set; } = string.Empty;
        [Required, MaxLength(128)]
        public string Email { get; set; } = string.Empty;
        [Required, MaxLength(256)]
        public string Password { get; set; } = string.Empty;
    }

    public class LoginDto
    {
        [Required, MaxLength(128)]
        public string Email { get; set; } = string.Empty;

        [Required, MaxLength(256)]
        public string Password { get; set; } = string.Empty;
    }
    public class AddRoleDto
    {
        [Required, MaxLength(128)]
        public string Email { get; set; } = string.Empty;

        public string RoleName { get; set; } = string.Empty;
    }
}

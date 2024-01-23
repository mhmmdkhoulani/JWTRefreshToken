using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace JsonWebToken.Models
{
    public class AppUser : IdentityUser
    {
        [Required, MaxLength(50)]
        public string FirstName { get; set; } = string.Empty;

        [Required, MaxLength(50)]
        public string LastName { get; set; } = string.Empty;

        public List<RefreshToken>? RefreshTokens { get; set; }
    }
}

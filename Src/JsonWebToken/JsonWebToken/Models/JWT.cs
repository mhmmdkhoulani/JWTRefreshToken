namespace JsonWebToken.Models
{
    public class JWT
    {
        public string Audience { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Key { get; set; } = string.Empty;
        public int DurationInMinutes { get; set; }
    }
}

namespace GuardianService.Model
{
    public class AccessToken
    {
        public string? value { get; set; }
        public bool? ssoUsed { get; set; }
        public bool? isActive { get; set; }
        public bool? isSSO { get; set; }
        public DateTime createdAt { get; set; }
        public DateTime expirationAt { get; set; }
        public int? expirationDuration { get; set; }
        public string? scopes { get; set; }
        public string? associatedClient { get; set; }
        public string? issuer { get; set; }
        public string? state { get; set; }
        public string? refreshToken { get; set; }
    }
}

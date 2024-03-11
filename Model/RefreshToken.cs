namespace GuardianService.Model
{
    public class RefreshToken
    {
        public int? tokenId { get; set; }
        public string? value { get; set; }
        public bool? isActive { get; set; }
        public DateTime createdAt { get; set; }
        public DateTime expirationAt { get; set; }
        public string? associatedClient { get; set; }
        public int? expirationDuration { get; set; }
        public string? lastAssociatedAccessToken { get; set; }
        public string? issuer { get; set; }
    }
}

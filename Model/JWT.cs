using System.Security.Permissions;

namespace GuardianService.Model
{
    public class JWT
    {
        public int? tokenId { get; set; }
        public string? jwtValue { get; set; }
        public string? associatedClient { get; set; }
        public string? issuer {  get; set; }
    }
}
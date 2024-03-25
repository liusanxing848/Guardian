namespace GuardianService.Issuer.Model
{
    public class GiftCard
    {
        public required string SN {  get; set; }
        public required string Issuer { get; set; }
        public required bool isValid { get; set; }
    }
}

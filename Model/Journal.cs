namespace GuardianService.Model
{
    public class Journal
    {
        public DateTime? transactionCreateTime { get; set; }
        public DateTime? recentUpdateTime { get; set; }
        public int? journalID { get; set; }
        public string? cardSN { get; set; }
        public string? associateClient {  get; set; }
        public string? guardianCodeHash { get; set; }
        public long? value { get; set; }
        public string? status { get; set; }
    }
}

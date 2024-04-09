using GuardianService.Services.AWS;

namespace GuardianService.Services
{
    public class Journal
    {
        public static void SaveJournal(Model.Journal journal) 
        {
            RDS.Journal.SaveJournal(journal);
        }

        public static bool VerifyJournal(Model.Journal journal) 
        {
            return RDS.Journal.CheckJournal(journal);
        }

        public static bool CheckExistingJournal (Model.Journal journal) 
        {
            return RDS.Journal.CheckExistingJournal(journal);
        }
    }
}

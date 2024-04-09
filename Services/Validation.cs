
namespace GuardianService.Services
{
    public class Validation
    {
        public static bool ValidateCard(string SN)
        {
            return AWS.RDS.Validation.ValidateCard(SN);
        }
    }
}

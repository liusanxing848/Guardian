using GuardianService.Configs;

namespace GuardianService.TEST
{
    public class LOCAL_DEBUG
    {
        public static void SHOW_GUARDIAN_CONFIGS()
        {
            Console.WriteLine($"RDS SERVER: {GUARDIAN_CONFIGS.RDS.SERVER}\n" +
                              $"RDS USERANME: {GUARDIAN_CONFIGS.RDS.USERNAME}\n" +
                              $"RDS PASSWORD: {GUARDIAN_CONFIGS.RDS.PASSWORD} \n" +
                              $"RDS PORT: {GUARDIAN_CONFIGS.RDS.PORT}\n\n" +
                              $"KMS ARN: {GUARDIAN_CONFIGS.KMS.ARN}\n" +
                              $"KMS AWS_ACCESS_KEY_ID: {GUARDIAN_CONFIGS.KMS.AWS_ACCESS_KEY_ID} \n" +
                              $"KMS AWS_SECRET_ACCESS_KEY: {GUARDIAN_CONFIGS.KMS.AWS_SECRET_ACCESS_KEY} \n" +
                              $"KMS REGION: {GUARDIAN_CONFIGS.KMS.REGION}");
        }
    }
}

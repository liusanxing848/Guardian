using Amazon;

namespace GuardianService.Configs
{
    public static class GUARDIAN_CONFIGS
    {
        public static class RDS
        {
            public static string SERVER;
            public static string USERNAME;
            public static string PASSWORD;
            public static string PORT;
        }

        public static class KMS
        {
            public static string ARN;
            public static string AWS_ACCESS_KEY_ID;
            public static string AWS_SECRET_ACCESS_KEY;
            public static RegionEndpoint REGION = RegionEndpoint.USWest2;
        }
    }
}

using Amazon;

namespace GuardianService.Configs
{
    public static class GUARDIAN_CONFIGS
    {
        public static class RDS
        {
            public static string? SERVER;
            public static string? DATABASE;
            public static string? USERNAME;
            public static string? PASSWORD;
            public static string? PORT;
        }

        public static class KMS
        {
            public static string? ARN;
            public static string? AWS_ACCESS_KEY_ID;
            public static string? AWS_SECRET_ACCESS_KEY;
            public static RegionEndpoint REGION = RegionEndpoint.USWest2;
        }

        public static class KMSENCRYPT
        {
            public static string? ARN;
            public static RegionEndpoint REGION = RegionEndpoint.USWest2;
        }
        public static class OAuth
        {
            public static int? TOKEN_LIFE_SPAN_30S;
            public static int? TOKEN_LIFE_SPAN_1M;
            public static int? TOKEN_LIFE_SPAN_5M;
            public static int? TOKEN_LIFE_SPAN_10M;
            public static int? TOKEN_LIFE_SPAN_30M;
            public static int? TOKEN_LIFE_SPAN_1H;
            public static int? TOKEN_LIFE_SPAN_2H;
            public static int? TOKEN_LIFE_SPAN_4H;
            public static int? TOKEN_LIFE_SPAN_6H;
            public static int? TOKEN_LIFE_SPAN_8H;
            public static int? TOKEN_LIFE_SPAN_12H;
            public static int? TOKEN_LIFE_SPAN_24H;
            public static int? TOKEN_LIFE_SPAN_48H;
            public static int? TOKEN_LIFE_SPAN_7D;
            public static int? TOKEN_LIFE_SPAN_14D;
            public static int? TOKEN_LIFE_SPAN_30D;

            public static string? TOKEN_STATE_ISSUED;
            public static string? TOKEN_STATE_ACTIVE;
            public static string? TOKEN_STATE_SUSPENDED;
            public static string? TOKEN_STATE_EXPIRED;
            public static string? TOKEN_STATE_REVOKED;
            public static string? TOKEN_STATE_REFRESHED;
            public static string? TOKEN_STATE_LOCKED;
        }
    }
}

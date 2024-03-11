using GuardianService.Configs;

namespace GuardianService.TEST
{
    public class LOCAL_DEBUG
    {
        public static void SHOW_GUARDIAN_CONFIGS()
        {
            Console.WriteLine($"RDS SERVER: {GUARDIAN_CONFIGS.RDS.SERVER}\n" +
                              $"RDS DATABASE: {GUARDIAN_CONFIGS.RDS.DATABASE}\n" +
                              $"RDS USERANME: {GUARDIAN_CONFIGS.RDS.USERNAME}\n" +
                              $"RDS PASSWORD: {GUARDIAN_CONFIGS.RDS.PASSWORD} \n" +
                              $"RDS PORT: {GUARDIAN_CONFIGS.RDS.PORT}\n\n" +
                              $"KMS ARN: {GUARDIAN_CONFIGS.KMS.ARN}\n" +
                              $"KMS AWS_ACCESS_KEY_ID: {GUARDIAN_CONFIGS.KMS.AWS_ACCESS_KEY_ID} \n" +
                              $"KMS AWS_SECRET_ACCESS_KEY: {GUARDIAN_CONFIGS.KMS.AWS_SECRET_ACCESS_KEY} \n" +
                              $"KMS REGION: {GUARDIAN_CONFIGS.KMS.REGION}");
        }

        public static void VALIDATE_SAMPLE_OAUTH_CLIENT()
        {
            string clientId = "77b177aa3835477cb709b7b6b3322c71";
            string clientSecret = "VJdunXmoTD8qDXwEkJs1Mb7p4Ihz20G2";
            Services.Auth.ValidateOAuthClient(clientId, clientSecret);
        }

        public static async Task GET_PUBLIC_KEY()
        {
            await Services.AWS.KMS.GetPublicKey();
        }
        public static async Task GET_JWT()
        {
            await Services.AWS.KMS.GetJWTWithPayloadOnly(new { });
        }
        public static async Task GetAccessToken()
        {
            await Services.AWS.KMS.GetAccessToken();
        }

        public static async Task GetRefreshToken()
        {
            await Services.AWS.KMS.GetRefreshToken();
        }

        private static void INSERT_TEST_ACCESSTOKEN_OBJ() //turn off to private, only need to load once
        {
            Model.AccessToken token = new Model.AccessToken();
            token.value = "testTokenValue";
            token.ssoUsed = false;
            token.isActive = true;
            token.isSSO = false;
            token.createdAt = DateTime.UtcNow;
            token.expirationDuration = GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_30D;
            token.expirationAt = Services.Auth.CalculateExpirationDateTime(token.createdAt, (int)token.expirationDuration!);
            token.scopes = "currently no scopes";
            token.associatedClient = "testClientId";
            token.refreshToken = "testRefreshTokenId";
            token.state = GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_ACTIVE;
            token.issuer = "Guardian";
            Services.AWS.RDS.Auth.SaveNewAccessToken(token);
        }
    }
}

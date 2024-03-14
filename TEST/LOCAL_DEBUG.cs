using GuardianService.Configs;
using Org.BouncyCastle.Tls;

namespace GuardianService.TEST
{
    public class LOCAL_DEBUG
    {
        public static async Task RUN_TEST()
        {
            //SHOW_GUARDIAN_CONFIGS();
            //GuardianService.Util.Guardian.RunAppConnectionCheckList();
            //GuardianService.Util.Data.AddOauthClient(); //only use when need add new client
            //GuardianService.TEST.LOCAL_DEBUG.VALIDATE_SAMPLE_OAUTH_CLIENT();
            //await GET_JWT();
            //await GetAccessToken();
            //await GetRefreshToken();
            //DEEP_CLEAN_REFRESH_TOKEN_TEST();
            //DEEP_CLEAN_ACCESS_TOKEN_TEST();
            //GET_REFRESHTOKEN_VALUE_FROM_CLIENTID("77b177aa3835477cb709b7b6b3322c71");
        }
        private static void SHOW_GUARDIAN_CONFIGS()
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

        private static void VALIDATE_SAMPLE_OAUTH_CLIENT()
        {
            string clientId = "77b177aa3835477cb709b7b6b3322c71";
            string clientSecret = "VJdunXmoTD8qDXwEkJs1Mb7p4Ihz20G2";
            Services.Auth.ValidateOAuthClient(clientId, clientSecret);
        }

        private static async Task GET_PUBLIC_KEY()
        {
            await Services.AWS.KMS.GetPublicKey();
        }
        private static async Task GET_JWT()
        {
            await Services.AWS.KMS.GetJWTWithPayloadOnly(new { });
        }
        private static async Task GetAccessToken()
        {
            await Services.AWS.KMS.GetAccessToken();
        }

        private static async Task GetRefreshToken()
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

        private static void DEEP_CLEAN_REFRESH_TOKEN_TEST()
        {
            Services.AWS.RDS.Auth.DeepCleanExpiredRefreshToken();
        }

        private static void DEEP_CLEAN_ACCESS_TOKEN_TEST()
        {
            Services.AWS.RDS.Auth.DeepCleanExpiredAccessToken();
        }
        private static void GET_REFRESHTOKEN_VALUE_FROM_CLIENTID(string clientId)
        {
            string value = Services.AWS.RDS.Auth.GetRefreshTokenValueFromClientId(clientId);
            Console.WriteLine("TEST, Refreshtoken value: " + value);
        }

        
    }
}

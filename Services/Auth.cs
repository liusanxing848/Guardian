using Amazon.Runtime.Internal.Transform;
using GuardianService.Util;

namespace GuardianService.Services
{
    public class Auth
    {
        public static bool ValidateOAuthClient(string clientId, string clientSecret)
        {
            bool clientValidationResult = AWS.RDS.Auth.ValidateOAuthClient(clientId, clientSecret);
            return clientValidationResult;
        }

        public static async Task<Model.AccessToken?> getAccessToken(string clientId)
        {
            //check client has live token
            KeyValuePair<bool, bool> clientHasliveTokenResult = AWS.RDS.Auth.CheckClientHasLiveToken(clientId);
            Console.WriteLine($"key: {clientHasliveTokenResult.Key}, value: {clientHasliveTokenResult.Value}");
            if (!clientHasliveTokenResult.Key && !clientHasliveTokenResult.Value)
            {
                GLogger.LogRed("ERR", "RDS", "RDS Connection error!");
                return null;
            }
            else
            {
                if(clientHasliveTokenResult.Key && clientHasliveTokenResult.Value)
                {
                    GLogger.Log("Renew AccessToken", $"Renew token for {clientId}");
                    return await Services.AWS.RDS.Auth.RenewAccessToken(clientId);
                }
                if(clientHasliveTokenResult.Key && !clientHasliveTokenResult.Value)
                {
                    GLogger.Log("Create AccessToken", $"Create token for {clientId}");
                    return await Services.AWS.RDS.Auth.CreateNewAccessTokenAttachRefreshToken(clientId);
                }
            }
            await Console.Out.WriteLineAsync("outputing null token?");
            return Util.Data.DUMMY_VOID_TOKEN(clientId) ;
        }

        public static DateTime CalculateExpirationDateTime(DateTime startTime, int duration)
        {
            DateTime expirationDateTime = startTime.AddSeconds(duration);
            return expirationDateTime;
        }

        public static async Task<bool> ValidateJWTToken(string jwtToken)
        {
            string publicKey = await Services.AWS.KMS.GetPublicKey();
            bool IsJWTValid = Services.AWS.KMS.VerifyJwt(jwtToken, publicKey);
            if (IsJWTValid) 
            {
                GLogger.LogGreen("Success", "JWT-Verification", $"{jwtToken} \nReturns VERIFIED!");   
            }
            else
            {
                GLogger.LogRed("Fail", "JWT-Verification", $"{jwtToken} \nReturns INVALID!");
            }

            return IsJWTValid;
        }
    }
}


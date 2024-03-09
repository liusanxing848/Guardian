namespace GuardianService.Services
{
    public class Auth
    {
        public static bool ValidateOAuthClient(string clientId, string clientSecret)
        {
            bool clientValidationResult = AWS.RDS.Auth.ValidateOAuthClient(clientId, clientSecret);
            return clientValidationResult;
        }
    }
}

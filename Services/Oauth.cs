using Microsoft.AspNetCore.Mvc;

namespace GuardianService.Services
{
    public class Oauth
    {
        public static bool ValidateOauthClientCredentials(string ClientId, string clientSecret)
        {
            //AWS RDS here.
            return true;
        }
    }
}

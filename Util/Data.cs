using GuardianService.Model;

namespace GuardianService.Util
{
    public class Data
    {
        public static void AddOauthClient()
        {
            OAuthClient client = new OAuthClient();
            client.clientID = "77b177aa3835477cb709b7b6b3322c71";
            client.clientSecret = "VJdunXmoTD8qDXwEkJs1Mb7p4Ihz20G2";
            client.clientName = "SMUQA";
            client.grantTypes = "client_credentials";
            client.businessCode = "SMUQA";
            client.isActive = true;

            Services.AWS.RDS.Auth.InsertNewOAuthClient(client);
        }
    }
}

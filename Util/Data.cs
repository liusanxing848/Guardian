using GuardianService.Configs;
using GuardianService.Model;
using Microsoft.IdentityModel.Tokens;

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
        }

        public static AccessToken DUMMY_VOID_TOKEN(string clientId)
        {
            AccessToken token = new AccessToken();
            token.value = "nullValueToken";
            token.isSSO = false;
            token.ssoUsed = false;
            token.issuer = "Guardian";
            token.state = GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_EXPIRED;
            token.expirationDuration = 0;
            token.createdAt = DateTime.UtcNow;
            token.expirationAt = DateTime.UtcNow;
            token.associatedClient = clientId;
            token.refreshToken = "null value";
            token.scopes = "null";
            token.isActive = false;
            return token;
        }
    }
}

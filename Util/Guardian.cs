using GuardianService.Configs;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace GuardianService.Util
{
    public class Guardian
    {
        public static void InitializeAppSettings()
        {
            string filePath = @"..\Guardian\Configs\";
            string kmsConfigFileName = "KMSConfigs.yaml";
            string rdsConfigFileName = "RDSConfigs.yaml";
            string oauthConfigFileName = "OAuthConfigs.yaml";

            LoadKMSConfigs(filePath + kmsConfigFileName);
            LoadRDSConfigs(filePath + rdsConfigFileName);
            LoadOAuthConfigs(filePath + oauthConfigFileName);

        }

        public static void RunAppConnectionCheckList()
        {
            Services.AWS.RDS.CheckAWSRDSConnection();
        }

        private static void LoadKMSConfigs(string path)
        {
            dynamic kmsConfigObj = DeserializeYAMLtoObject(path);
            GUARDIAN_CONFIGS.KMS.ARN = kmsConfigObj["ARN"];
            GUARDIAN_CONFIGS.KMS.AWS_SECRET_ACCESS_KEY = kmsConfigObj["AWS_SECRET_ACCESS_KEY"];
            GUARDIAN_CONFIGS.KMS.AWS_ACCESS_KEY_ID = kmsConfigObj["AWS_ACCESS_KEY_ID"];

        }
        
        private static void LoadRDSConfigs(string path)
        {
            dynamic rdsConfigObj = DeserializeYAMLtoObject(path);
            GUARDIAN_CONFIGS.RDS.SERVER = rdsConfigObj["SERVER"];
            GUARDIAN_CONFIGS.RDS.DATABASE = rdsConfigObj["DATABASE"];
            GUARDIAN_CONFIGS.RDS.USERNAME = rdsConfigObj["USERNAME"];
            GUARDIAN_CONFIGS.RDS.PASSWORD = rdsConfigObj["PASSWORD"];
            GUARDIAN_CONFIGS.RDS.PORT = rdsConfigObj["PORT"];
        }

        private static void LoadOAuthConfigs(string path)
        {
            dynamic oauthConfigObj = DeserializeYAMLtoObject(path);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_30S = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_30S"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_1M = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_1M"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_5M = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_5M"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_10M = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_10M"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_30M = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_30M"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_1H = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_1H"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_2H = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_2H"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_4H = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_4H"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_6H = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_6H"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_8H = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_8H"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_12H = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_12H"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_24H = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_24H"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_48H = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_48H"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_7D = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_7D"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_14D = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_14D"]);
            GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_30D = int.Parse(oauthConfigObj["TOKEN_LIFE_SPAN_30D"]);

            GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_ISSUED = oauthConfigObj["TOKEN_STATE_ISSUED"];
            GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_ACTIVE = oauthConfigObj["TOKEN_STATE_ACTIVE"];
            GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_SUSPENDED = oauthConfigObj["TOKEN_STATE_SUSPENDED"];
            GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_EXPIRED = oauthConfigObj["TOKEN_STATE_EXPIRED"];
            GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_REVOKED = oauthConfigObj["TOKEN_STATE_REVOKED"];
            GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_REFRESHED = oauthConfigObj["TOKEN_STATE_REFRESHED"];
            GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_LOCKED = oauthConfigObj["TOKEN_STATE_LOCKED"];

        }

        private protected static dynamic DeserializeYAMLtoObject(string path)
        {
            string yamlContent = File.ReadAllText(path);
            return new DeserializerBuilder()
                             .WithNamingConvention(UnderscoredNamingConvention.Instance)
                             .Build()
                             .Deserialize<dynamic>(yamlContent);
        }
    }
}

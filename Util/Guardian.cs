using GuardianService.Configs;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace GuardianService.Util
{
    public class Guardian
    {
        public static void InitializeAppSettings()
        {
            string filePath = @"..\Guardian\Configs";
            string kmsConfigFileName = "KMSConfigs.yaml";
            string rdsConfigFileName = "RDSConfigs.yaml";

            LoadKMSConfigs(filePath + kmsConfigFileName);
            LoadRDSConfigs(filePath + rdsConfigFileName);
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
            GUARDIAN_CONFIGS.RDS.USERNAME = rdsConfigObj["USERNAME"];
            GUARDIAN_CONFIGS.RDS.PASSWORD = rdsConfigObj["PASSWORD"];
            GUARDIAN_CONFIGS.RDS.PORT = rdsConfigObj["PORT"];
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

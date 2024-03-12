using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using GuardianService.Configs;
using GuardianService.Model;
using GuardianService.Util;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;


namespace GuardianService.Services.AWS
{
    public class KMS
    {
        static AmazonKeyManagementServiceClient? kmsClient;
        static string? PUBLIC_KEY;
        
        static KMS()
        {
            bool kmsIsLoaded = KMSpreloadCheck();
            if(kmsIsLoaded) 
            {
                kmsClient = new AmazonKeyManagementServiceClient(GUARDIAN_CONFIGS.KMS.AWS_ACCESS_KEY_ID, 
                                                                 GUARDIAN_CONFIGS.KMS.AWS_SECRET_ACCESS_KEY, 
                                                                 GUARDIAN_CONFIGS.KMS.REGION);
            }
            else
            {
                Guardian.InitializeAppSettings();
                kmsClient = new AmazonKeyManagementServiceClient(GUARDIAN_CONFIGS.KMS.AWS_ACCESS_KEY_ID,
                                                                 GUARDIAN_CONFIGS.KMS.AWS_SECRET_ACCESS_KEY,
                                                                 GUARDIAN_CONFIGS.KMS.REGION);
            }
            GetPublicKey();
        }


        public static async Task<string> GetPublicKey()
        {
            GetPublicKeyRequest request = new GetPublicKeyRequest
            {
                KeyId = GUARDIAN_CONFIGS.KMS.ARN
            };

            try
            {
                GetPublicKeyResponse response = await kmsClient!.GetPublicKeyAsync(request);
                string publicKey = Convert.ToBase64String(response.PublicKey.ToArray());
                GLogger.Log("KMS", "Get Public key: " + publicKey);
                if(PUBLIC_KEY != publicKey)
                {
                    PUBLIC_KEY = publicKey;
                }
                return publicKey;
            }
            catch (Exception ex)
            {
                GLogger.LogRed("ERR", "KMS", "Failed to get Public key: " + ex);
            }
            return "error";
        }

        public static async Task<string> GetJWTWithPayloadOnly(dynamic payload)
        {
            dynamic header = new
            {
                alg = "RS256",
                typ = "JWT"
            };

            string JsonHeader = Newtonsoft.Json.JsonConvert.SerializeObject(header);
            string JsonPayload = Newtonsoft.Json.JsonConvert.SerializeObject(payload);

            string encodedHeader = Base64UrlEncode(JsonHeader);
            string encodedPayload = Base64UrlEncode(JsonPayload);

            string signingInput = encodedHeader + "." + encodedPayload;

            SignRequest signRequest = new SignRequest
            {
                KeyId = GUARDIAN_CONFIGS.KMS.ARN,
                MessageType = MessageType.RAW,
                SigningAlgorithm = SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256,
                Message = new MemoryStream(Encoding.UTF8.GetBytes(signingInput))
            };

            try
            {
                SignResponse signingResponse = await kmsClient!.SignAsync(signRequest);
                byte[] signature = signingResponse.Signature.ToArray();
                string encodedSignature = Base64UrlEncode(signature);
                string jwt = $"{encodedHeader}.{encodedPayload}.{encodedSignature}";
                GLogger.LogGreen("SUCCESS", "JWT", $"Value: {jwt}");
                return jwt;
            }
            catch (Exception ex) 
            {
                GLogger.LogRed("ERR", "JWT", $"Failed to get JWT, Reason: " + ex.Message);
            }
            return "error";

        }

        public static async Task<string> GetAccessToken()
        {
            try
            {
                dynamic request = new GenerateRandomRequest
                {
                    NumberOfBytes = 32
                };

                GenerateRandomResponse response = await kmsClient!.GenerateRandomAsync(request);

                string accessToken = Convert.ToBase64String(response.Plaintext.ToArray());
                GLogger.LogGreen("SUCCESS", "Access-Token", $"Value: {accessToken}");
                return accessToken;
            }
            catch(Exception ex)
            {
                GLogger.LogRed("ERR", "AccessToken", $"Failed to get Access Token, Reason: " + ex.Message);
                return "error";
            }
        }

        public static async Task<string> GetRefreshToken()
        {
            try
            {
                dynamic request = new GenerateRandomRequest
                {
                    NumberOfBytes = 256
                };

                GenerateRandomResponse response = await kmsClient!.GenerateRandomAsync(request);

                string refreshToken = Convert.ToBase64String(response.Plaintext.ToArray());
                GLogger.LogGreen("SUCCESS", "Refresh-Token", $"Value: {refreshToken}");
                return refreshToken;
            }
            catch (Exception ex)
            {
                GLogger.LogRed("ERR", "RefreshToken", $"Failed to get Access Token, Reason: " + ex.Message);
                return "error";
            }
        }

        public static bool VerifyJwt(string jwtToken, string publicKeyBase64)
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtSecurityToken = handler.ReadJwtToken(jwtToken);

            string encodedHeaderPayload = $"{Base64UrlEncode(jwtSecurityToken.Header.SerializeToJson())}.{Base64UrlEncode(jwtSecurityToken.Payload.SerializeToJson())}";
            byte[] signature = Base64UrlDecode(jwtSecurityToken.RawSignature);

            return GetRsaProviderFromBase64EncodedPublicKey(publicKeyBase64)
                   .VerifyData(Encoding.UTF8.GetBytes(encodedHeaderPayload), SHA256.Create(), signature);

        }
        private static bool KMSpreloadCheck()
        {
            if (string.IsNullOrEmpty(GUARDIAN_CONFIGS.KMS.ARN) ||
                string.IsNullOrEmpty(GUARDIAN_CONFIGS.KMS.AWS_ACCESS_KEY_ID) ||
                string.IsNullOrEmpty(GUARDIAN_CONFIGS.KMS.AWS_SECRET_ACCESS_KEY) ||
                GUARDIAN_CONFIGS.KMS.REGION == null)
            {
                GLogger.Log("KMS", "Found field of KMS is not loaded");
                return false;
            }
            else
            {
                GLogger.Log("KMS", "KMS config been loaded");
                return true;
            }
        }

        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input)
                .Replace('+', '-')
                .Replace('/', '_')
                .Replace("=", ""); // Remove padding for Base64Url
            return output;
        }

        private static string Base64UrlEncode(string input)
        {
            var output = Convert.ToBase64String(Encoding.UTF8.GetBytes(input))
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
            return output;
        }
        private static byte[] Base64UrlDecode(string input)
        {
            string output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding

            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new Exception("Illegal base64url string!");
            }

            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
        private static RSACryptoServiceProvider GetRsaProviderFromBase64EncodedPublicKey(string publicKeyBase64)
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            return rsaProvider;
        }
    }
}

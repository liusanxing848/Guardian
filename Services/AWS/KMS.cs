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

        public static async Task<string> GetRandomNumber()
        {
            try
            {
                dynamic request = new GenerateRandomRequest
                {
                    NumberOfBytes = 4
                };

                GenerateRandomResponse response = await kmsClient!.GenerateRandomAsync(request);

                byte[] randomBytes = response.Plaintext.ToArray();

                // Convert 4 bytes to an unsigned 32-bit integer
                uint randomValue = BitConverter.ToUInt32(randomBytes, 0);

                // Ensure the value is within the 0-999999 range
                uint sixDigitNumber = randomValue % 1000000;
                string code = sixDigitNumber.ToString();
                GLogger.LogGreen("SUCCESS", "GuardianCode", $"Value: {code}");
                return code;
            }
            catch (Exception ex)
            {
                GLogger.LogRed("ERR", "AccessToken", $"Failed to get Guardian code, Reason: " + ex.Message);
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

        public static string EncryptNumericCode(string numericCode)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.GenerateKey();
                aesAlg.GenerateIV();

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(numericCode);
                        }
                    }
                    GLogger.LogGreen("SUCCESS", "GUARDIAN-CODE", $"Succesfuly Hashed code: {numericCode}!");
                    // Convert the encrypted bytes to a Base64 string
                    return Convert.ToBase64String(msEncrypt.ToArray()) + ":" +
                           Convert.ToBase64String(aesAlg.Key) + ":" +
                           Convert.ToBase64String(aesAlg.IV);
                }
            }
        }

        public static string DecryptHashtoCode(string hash)
        {
            // Split the combined string to get the cipherText, Key, and IV
            string[] parts = hash.Split(':');
            if (parts.Length != 3)
                throw new ArgumentException("The hash does not contain all required parts.");

            byte[] cipherText = Convert.FromBase64String(parts[0]);
            byte[] Key = Convert.FromBase64String(parts[1]);
            byte[] IV = Convert.FromBase64String(parts[2]);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(csDecrypt))
                        {
                            GLogger.LogGreen("SUCCESS", "GUARDIAN-CODE", $"Succesfuly Decrypted hash: {hash}!");
                            return reader.ReadToEnd();
                        }
                    }
                }
            }
        }
    

        public static bool VerifyJwt(string jwtToken, string publicKeyBase64)
        {
            GLogger.LogYellow("VERYFY", "JWT", $"Starting JWT verification for token: {jwtToken}");
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
            GLogger.Log("BASE_64", $"Encode BYTE TYPE:{input}");
            return output;
        }

        private static string Base64UrlEncode(string input)
        {
            var output = Convert.ToBase64String(Encoding.UTF8.GetBytes(input))
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
            GLogger.Log("BASE_64", $"Encode STRING TYPE:{input}");
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
            GLogger.Log("BASE_64", $"Decode STRING TYPE:{input}");
            return converted;
        }
        private static RSACryptoServiceProvider GetRsaProviderFromBase64EncodedPublicKey(string publicKeyBase64)
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            GLogger.LogGreen("INIT", "KMS", "Initializing... create RSA Ctypo Service Provider instance");
            return rsaProvider;
        }

    }
}

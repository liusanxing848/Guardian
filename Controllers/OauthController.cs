using GuardianService.Model;
using GuardianService.Services.AWS;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace GuardianService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class OauthController : ControllerBase
    {
        IConfiguration configuration;
        public OauthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        [HttpPost("getPublicKey")]
        [AllowAnonymous]
        public async Task<IActionResult> GetPublicKey([FromHeader(Name = "Authorization")] string authorization, [FromForm] string grant_type)
        {
            // Check for Basic Authentication and grant_type
            if (string.IsNullOrWhiteSpace(authorization) || !authorization.StartsWith("Basic ") || grant_type != "client_credentials")
            {
                return Unauthorized();
            }

            // Extract credentials from Authorization header
            string encodedCredentials = authorization.Substring("Basic ".Length).Trim();
            string decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
            string[] headerCredentials = decodedCredentials.Split(':');

            if (headerCredentials.Length != 2)
            {
                return Unauthorized();
            }

            string clientId = headerCredentials[0];
            string clientSecret = headerCredentials[1];

            //Validate client credentials
            bool clientValidated = Services.Auth.ValidateOAuthClient(clientId, clientSecret);

            if (!clientValidated)
            {
                return Unauthorized();
            }

            string publicKey = await Services.AWS.KMS.GetPublicKey();

            dynamic returnBody = new
            {
                app = "Guardian",
                time = DateTime.UtcNow,
                sub = clientId,
                publickey = publicKey
            };

            return Ok(returnBody);
        }

        [HttpPost("token")]
        [AllowAnonymous]
        public async Task<IActionResult> Token([FromHeader(Name = "Authorization")] string authorization, [FromForm] string grant_type)
        {
            // Check for Basic Authentication and grant_type
            if (string.IsNullOrWhiteSpace(authorization) || !authorization.StartsWith("Basic ") || grant_type != "client_credentials")
            {
                return Unauthorized();
            }

            // Extract credentials from Authorization header
            string encodedCredentials = authorization.Substring("Basic ".Length).Trim();
            string decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
            string[] headerCredentials = decodedCredentials.Split(':');

            if (headerCredentials.Length != 2)
            {
                return Unauthorized();
            }

            string clientId = headerCredentials[0];
            string clientSecret = headerCredentials[1];

            //Validate client credentials
            bool clientValidated =  Services.Auth.ValidateOAuthClient(clientId, clientSecret);

            if(!clientValidated) 
            {
                return Unauthorized();
            }


            //generate actual access token value
            Model.AccessToken? accessToken = await Services.Auth.getAccessToken(clientId);
            dynamic payload = new
            {
                token_type = "bearer",
                access_token = accessToken!.value,
                expireTime_zulu = accessToken.expirationAt,
                isSSO = accessToken.isSSO,
                scopes = accessToken.scopes,
                refreshToken = accessToken.refreshToken,
                sub = clientId
            };

            string jwtTokenValue = await Services.AWS.KMS.GetJWTWithPayloadOnly(payload);

            dynamic returnBody = new
            {
                JWT_value = jwtTokenValue,
                alg = "RS256"
            };

            return Ok(returnBody);
        }

        [HttpPost("verifyJWT")]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyJWTToken([FromHeader(Name = "Authorization")] string authorization, [FromBody] JsonElement jsonElement)
        {
            await Console.Out.WriteLineAsync("received request");
            // Check for Basic Authentication and grant_type
            if (string.IsNullOrWhiteSpace(authorization) || !authorization.StartsWith("Basic "))
            {
                await Console.Out.WriteLineAsync("failed at the header");
                return Unauthorized();
            }

            // Extract credentials from Authorization header
            string encodedCredentials = authorization.Substring("Basic ".Length).Trim();
            string decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
            string[] headerCredentials = decodedCredentials.Split(':');

            if (headerCredentials.Length != 2)
            {
                await Console.Out.WriteLineAsync("failed at wrong credential format");

                return Unauthorized();
            }

            string clientId = headerCredentials[0];
            string clientSecret = headerCredentials[1];

            //Validate client credentials
            bool clientValidated = Services.Auth.ValidateOAuthClient(clientId, clientSecret);

            if (!clientValidated)
            {
                await Console.Out.WriteLineAsync("failed to verify client");
                return Unauthorized();
            }

            //Working on Body
            if (jsonElement.TryGetProperty("jwt", out JsonElement jwtTokenElement))
            {
                string jwtToken = jwtTokenElement.GetString()!;

                // Now that you have the JWT token, you can verify it or use it as needed
                // For example, verify the token
                bool isValidToken = await Services.Auth.ValidateJWTToken(jwtToken);

                if (isValidToken)
                {
                    // Token is valid, continue with your logic
                    return Ok(new {JWT = "VALID!"}); // Or any appropriate action result
                }
                else
                {
                    // Token is invalid or verification failed
                    return Ok(new { JWT = "NOT VALID!" }); // Or any appropriate action result based on your security logic
                }
            }
            else
            {
                // "jwt" property not found in the JSON body
                return BadRequest("JWT token is missing.");
            }

        }

        [HttpPost("accessTokenRetroSpect")]
        [AllowAnonymous]
        public IActionResult AccessTokenRetroSpect([FromHeader(Name = "Authorization")] string authorization, [FromBody] JsonElement jsonElement)
        {
            if (string.IsNullOrWhiteSpace(authorization) || !authorization.StartsWith("Basic "))
            {
                //await Console.Out.WriteLineAsync("failed at the header");
                return Unauthorized();
            }

            // Extract credentials from Authorization header
            string encodedCredentials = authorization.Substring("Basic ".Length).Trim();
            string decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
            string[] headerCredentials = decodedCredentials.Split(':');

            if (headerCredentials.Length != 2)
            {
                //await Console.Out.WriteLineAsync("failed at wrong credential format");

                return Unauthorized();
            }

            string clientId = headerCredentials[0];
            string clientSecret = headerCredentials[1];

            //Validate client credentials
            bool clientValidated = Services.Auth.ValidateOAuthClient(clientId, clientSecret);

            if (!clientValidated)
            {
                //await Console.Out.WriteLineAsync("failed to verify client");
                return Unauthorized();
            }


            //Working on Body
            if (jsonElement.TryGetProperty("accessToken", out JsonElement accessTokenElement))
            {
                string accessToken = accessTokenElement.GetString()!;

                Model.AccessToken returningTokenObj = Services.Auth.GetAccessTokenByValue(accessToken);

                if (returningTokenObj != null)
                {
                    dynamic returnBody = new
                    {
                        accessToken = returningTokenObj.value,
                        isSSO = returningTokenObj.isSSO,
                        ssoUsed = returningTokenObj.ssoUsed,
                        isActive = returningTokenObj.isActive,
                        state = returningTokenObj.state,
                        scopes = returningTokenObj.scopes,
                        expirationAt = returningTokenObj.expirationAt,
                        associatedClient = returningTokenObj.associatedClient,
                        issuer = returningTokenObj.issuer,
                    };
                    // Token is valid, continue with your logic
                    return Ok(returnBody); // Or any appropriate action result
                }
                else
                {
                    dynamic returnNullBody = new
                    {
                        error = "Failed to get this token"
                    };
                    return Ok(returnNullBody); // Or any appropriate action result based on your security logic
                }
            }
            else
            {
                // "jwt" property not found in the JSON body
                return BadRequest("bad request.");
            }
        }

        [HttpPost("refreshTokenRetroSpect")]
        [AllowAnonymous]
        public IActionResult RefreshTokenRetroSpect([FromHeader(Name = "Authorization")] string authorization, [FromBody] JsonElement jsonElement)
        {
            if (string.IsNullOrWhiteSpace(authorization) || !authorization.StartsWith("Basic "))
            {
                //await Console.Out.WriteLineAsync("failed at the header");
                return Unauthorized();
            }

            // Extract credentials from Authorization header
            string encodedCredentials = authorization.Substring("Basic ".Length).Trim();
            string decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
            string[] headerCredentials = decodedCredentials.Split(':');

            if (headerCredentials.Length != 2)
            {
                //await Console.Out.WriteLineAsync("failed at wrong credential format");

                return Unauthorized();
            }

            string clientId = headerCredentials[0];
            string clientSecret = headerCredentials[1];

            //Validate client credentials
            bool clientValidated = Services.Auth.ValidateOAuthClient(clientId, clientSecret);

            if (!clientValidated)
            {
                //await Console.Out.WriteLineAsync("failed to verify client");
                return Unauthorized();
            }


            //Working on Body
            if (jsonElement.TryGetProperty("refreshToken", out JsonElement refreshTokenElement))
            {
                string refreshToken = refreshTokenElement.GetString()!;

                Model.RefreshToken returningTokenObj = Services.Auth.GetRrefreshTokenByValue(refreshToken);

                if (returningTokenObj != null && clientId == returningTokenObj.associatedClient)
                {
                    dynamic returnBody = new
                    {
                        refreshToken = returningTokenObj.value,
                        isActive = returningTokenObj.isActive,
                        expirationAt = returningTokenObj.expirationAt,
                        associatedClient = returningTokenObj.associatedClient,
                        issuer = returningTokenObj.issuer,
                    };
                    // Token is valid, continue with your logic
                    return Ok(returnBody); // Or any appropriate action result
                }
                else if(returningTokenObj != null && clientId != returningTokenObj.associatedClient)
                {
                    dynamic returnWarninglBody = new
                    {
                        error = "This is not your token!"
                    };
                    return Ok(returnWarninglBody); 
                }
                else
                {
                    dynamic returnErrorlBody = new
                    {
                        error = "Failed to get token"
                    };
                    return Ok(returnErrorlBody);
                }
            }
            else
            {
                // "jwt" property not found in the JSON body
                return BadRequest("bad request.");
            }
        }
    }
}

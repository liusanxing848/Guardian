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
        public IActionResult GetPublicKey(
            [FromHeader(Name = "Authorization")] string authorization,
            [FromForm] string grant_type)
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

            string publicKey = Services.AWS.KMS.GetPublicKey();

            dynamic returnBody = new
            {
                app = "Guardian",
                time = DateTime.Now,
                sub = clientId,
                publickey = publicKey
            };

            return Ok(returnBody);
        }

        [HttpPost("token")]
        [AllowAnonymous]
        public IActionResult Token(
            [FromHeader(Name = "Authorization")] string authorization,
            [FromForm] string grant_type)
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


            //JWT
            var issuer = configuration["Jwt:Issuer"];
            var audience = configuration["Jwt:Audience"];
            var key = Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!);

            var signingCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha512Signature
                    );




            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                new Claim(ClaimTypes.Name, "a test game"),
                new Claim(JwtRegisteredClaimNames.Sub, "clientID"),
                new Claim(JwtRegisteredClaimNames.Email, "client@company.com"),

                }),
                Issuer = issuer,
                Audience = audience,
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = signingCredentials
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = tokenHandler.WriteToken(token);
            return Ok(new { access_token = jwtToken, token_type = "bearer" });
        }

        [HttpPost("verify")]
        [Authorize]
        public IActionResult Verify([FromBody] JsonElement jsonElement)
        {
            return Ok(new { message = "JWT ok!" });
        }
    }
}

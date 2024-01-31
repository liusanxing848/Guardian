using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace GuardianService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class OauthController : ControllerBase
    {
        [HttpPost("token")]
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
            var encodedCredentials = authorization.Substring("Basic ".Length).Trim();
            var decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
            var credentials = decodedCredentials.Split(':');

            if (credentials.Length != 2)
            {
                return Unauthorized();
            }

            var client_id = credentials[0];
            var client_secret = credentials[1];

            // Validate client_id and client_secret
            // Replace this with your validation logic
            if (client_id != "123" || client_secret != "abc")
            {
                return Unauthorized();
            }

            //var token = GenerateJwtToken();
            return Ok(new { access_token = "tokenPlaceHolder", token_type = "bearer" });
        }
    }
}

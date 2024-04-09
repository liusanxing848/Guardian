using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace GuardianService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ValidationController : ControllerBase
    {

        [HttpPost("validateCard")]
        [AllowAnonymous]
        public IActionResult ValidateCard([FromHeader(Name = "Authorization")] string authorization, [FromBody] JsonElement jsonElement)
        {
            if (string.IsNullOrWhiteSpace(authorization) || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return Unauthorized("Authorization header is either empty or doesn't contain a Bearer token.");
            }
            string token = authorization.Substring("Bearer ".Length).Trim();

            //validate token
            bool isTokenValidate = Services.Auth.ValidateAccessToken(token);

            if (!isTokenValidate) 
            {
                return Unauthorized();
            }

            if (jsonElement.TryGetProperty("SN", out JsonElement cardInfoElement))
            {
                string serialNumber = cardInfoElement.ToString();
                //check serialNumber
                if(Services.Validation.ValidateCard(serialNumber))
                {
                    dynamic successBody = new
                    {
                        SN = serialNumber,
                        isValid = true
                    };
                    return Ok(successBody);
                }
                else
                {
                    dynamic invalidBody = new
                    {
                        SN = serialNumber,
                        isValid = false
                    };
                    return Ok(invalidBody);
                }
                
            }

            return BadRequest();
        }
    }
}

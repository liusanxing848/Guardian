using GuardianService.Util;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using YamlDotNet.Serialization.BufferedDeserialization;

namespace GuardianService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class RedeemController : ControllerBase
    {
        [HttpPost("redeemCard")]
        [AllowAnonymous]
        public IActionResult RedeemCard([FromHeader(Name = "Authorization")] string authorization, [FromBody] JsonElement jsonElement)
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

            string cardSN = "";
            string guardianCode = "";
            if (jsonElement.TryGetProperty("SN", out JsonElement cardInfoElement))
            {
                cardSN = cardInfoElement.ToString();            
            }
            if (jsonElement.TryGetProperty("guardianCode", out JsonElement guardianCodeElement))
            {
                guardianCode = guardianCodeElement.ToString();
            }
            
            //check guardian code
            bool checkResult = Services.Redeem.CheckGuardianCode(cardSN, guardianCode);
            GLogger.LogRed("guardianCode missmatch", "Redeem Controller", $"{guardianCode} is not match!");
            if(!checkResult)
            {
                //check retry left:
                int retryLeft = Services.Redeem.CheckGuardiaCodeRetryLeft(cardSN);
                {
                    if (retryLeft <=  0) 
                    {
                        //initiate lock card
                        Services.Redeem.LockCard(cardSN);

                        //return body

                        dynamic lockCardRespond = new
                        {
                            warning = "You ran out of retry Time! Please contact merchant! Your card is locked"
                        };
                        return Ok(lockCardRespond);
                    }
                }
                // deduct trytime
                Services.Redeem.DeductCardRetryTime(cardSN);

                //check try time and give resp
                int retryRemain = Services.Redeem.CheckGuardiaCodeRetryLeft(cardSN);
                dynamic failedToValidateResp = new
                {
                    warning = "Your code is INCORRECT! Your retry chance is limited!",
                    retryLeft = retryRemain,
                    card = cardSN,
                };
                return Ok(failedToValidateResp);
            }

            //peform change status
            Services.Redeem.RedeemCard(cardSN);
            dynamic successResp = new
            {
                Status = "Success!",
                card = cardSN
            };


            return Ok(successResp);
        }
    }
}

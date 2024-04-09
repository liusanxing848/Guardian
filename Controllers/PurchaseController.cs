using GuardianService.Model;
using GuardianService.Services.AWS;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace GuardianService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class PurchaseController : ControllerBase
    {
        [HttpPost("generateCode")]
        [AllowAnonymous]
        public async Task<IActionResult> GenerateGuardianCode([FromHeader(Name = "Authorization")] string authorization, [FromBody] JsonElement jsonElement)
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

            string cardSN="";
            if (jsonElement.TryGetProperty("SN", out JsonElement snInfoElement))
            {
                cardSN = snInfoElement.ToString();
            }

            string associateClient="";
            if (jsonElement.TryGetProperty("associateClient", out JsonElement clientInfoElement))
            {
                associateClient = clientInfoElement.ToString();
            }

            long cardValue = 0;
            if (jsonElement.TryGetProperty("cardValue", out JsonElement valueInfoElement))
            {
                if (valueInfoElement.TryGetInt64(out long extractedAmount))
                {
                    cardValue = extractedAmount;
                }
                    
            }

            string guardianCode = await KMS.GetRandomNumber();
            string hashedCode = KMS.EncryptNumericCode(guardianCode);

            Journal journal = new Journal();
            journal.transactionCreateTime = DateTime.UtcNow;
            journal.recentUpdateTime = DateTime.UtcNow;
            journal.cardSN = cardSN;
            journal.associateClient = associateClient;
            journal.guardianCodeHash = hashedCode;
            journal.value = cardValue;
            journal.status = "REDEEM PENDING";
            
            //before save, check if exist. 
            bool currentJournalExists = Services.Journal.CheckExistingJournal(journal);
            if (currentJournalExists) 
            {
                dynamic existJournalResp = new
                {
                    error = "current card been registered in Guardian, plese use different card."
                };
                return Ok(existJournalResp);
            }

            //start saving the code to the db
            Services.Journal.SaveJournal(journal);

            //Verify journal
            bool isChecked = Services.Journal.VerifyJournal(journal);
            if (isChecked)
            {
                dynamic successReceipt = new
                {
                    Status = "success",
                    card = cardSN,
                    GuardianCode = guardianCode
                };

                return Ok(successReceipt);
            }
            //here should have a sophisticated retry logic

            dynamic failedReceipt = new
            {
                issue = "something went wrong, please retry"
            };
            return BadRequest(failedReceipt);
        }
    }
}

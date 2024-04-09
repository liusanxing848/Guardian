
using GuardianService.Util;

namespace GuardianService.Services
{
    public class Redeem
    {
        public static bool CheckGuardianCode(string cardSN, string guardianCode)
        {
            //step one, get code Hash
            string codeHash = AWS.RDS.Journal.GetGuardianHashFromCardSN(cardSN);
            GLogger.LogYellow("Saved Hash", "RDS", $"{codeHash}");

            //decrypt the hash
            string decryptedHash = AWS.KMS.DecryptHashtoCode(codeHash);
            GLogger.LogYellow("Decrypted Hash", "KMS", $"{decryptedHash}");
            if (guardianCode != decryptedHash)
            {
                return false;
            }
            return true;
        }

        public static int CheckGuardiaCodeRetryLeft (string cardSN)
        {
            return AWS.RDS.Journal.CheckLeftRetryValue(cardSN);
        }

        public static void LockCard (string cardSN) 
        {
            AWS.RDS.Journal.LockCard(cardSN);
        }

        public static void DeductCardRetryTime (string cardSN) 
        {
            AWS.RDS.Journal.FailedGuardianCodeDeductRetry(cardSN);
        }

        public static void RedeemCard(string cardSN)
        {
            AWS.RDS.Journal.StatusChangeToRedeemed(cardSN);
        }
    }
}

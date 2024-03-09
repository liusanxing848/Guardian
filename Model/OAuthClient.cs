namespace GuardianService.Model
{
    public class OAuthClient
    {
        public string? clientID; //DB: clientId VARCHAR(255) PRIMARY KEY,
        public string? clientSecret; //DB: clientSecret VARCHAR(255) NOT NULL
        public string? clientName; //DB: clientName VARCHAR(255) NOT NULL
        public string? grantTypes; //DB: granttypes VARCHAR(255) NOT NULL
        public string? clientStatus; //DB: clientStatus VARCHAR(255)
        public string? businessCode; //DB: businessCode VARCHAR(255) NOT NULL
        public DateTime? createdAt; //DB: createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        public DateTime? updateAt; //DB: updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        public bool? isActive; //DB: isActive BOOLEAN DEFAULT FALSE
    }
}

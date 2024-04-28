using GuardianService.Configs;
using GuardianService.Model;
using GuardianService.Util;
using Microsoft.Extensions.Logging.Abstractions;
using MySql.Data.MySqlClient;
using MySqlX.XDevAPI;
using Org.BouncyCastle.Utilities;
using System.Data;
using System.Runtime.CompilerServices;
using YamlDotNet.Serialization.NodeDeserializers;

namespace GuardianService.Services.AWS
{
    public class RDS
    {
        static string connectionString;
        private static MySqlConnection? conn = null;

        static RDS()
        {
            GLogger.LogGreen("INIT", "RDS", "Initialize RDS");
            connectionString = $"Server={GUARDIAN_CONFIGS.RDS.SERVER}; " +
                               $"Database={GUARDIAN_CONFIGS.RDS.DATABASE}; " +
                               $"UID={GUARDIAN_CONFIGS.RDS.USERNAME}; " +
                               $"password={GUARDIAN_CONFIGS.RDS.PASSWORD}; " +
                               $"Port={GUARDIAN_CONFIGS.RDS.PORT}; ";
        }

        public static void ChangeToIssuerDB()
        {
            GLogger.LogYellow("RDS-Config", "RDS", "Switch RDS db");
            connectionString = $"Server={GUARDIAN_CONFIGS.RDS.SERVER}; " +
                               $"Database=Issuer; " +
                               $"UID={GUARDIAN_CONFIGS.RDS.USERNAME}; " +
                               $"password={GUARDIAN_CONFIGS.RDS.PASSWORD}; " +
                               $"Port={GUARDIAN_CONFIGS.RDS.PORT}; ";
        }
        public static bool CheckAWSRDSConnection()
        {
            GLogger.LogYellow("STATUS", "RDS", "Checking RDS status...");
            if(!string.IsNullOrEmpty(connectionString)) 
            {
                try
                {
                    using(MySqlConnection conn = new MySqlConnection(connectionString))
                    {
                        conn.Open();
                        GLogger.LogGreen("SUCCESS","RDS", "Connected to RDS!");
                        return true;
                    }
                }
                catch (Exception e)
                {
                    GLogger.LogRed("ERR", "RDS", $"Failed to connect: {e}");
                    return false;
                }
            }
            else
            {
                GLogger.LogRed("ERR", "RDS", "Connection string is empty or null");
                return false;
            }
        }

        private static void ShowTables()
        {
            string query = @"SHOW TABLES";
            bool connected = TryConnect();
            if (connected)
            {
                MySqlCommand command = new MySqlCommand(query, conn);
                MySqlDataReader reader = command.ExecuteReader();
                while (reader.Read()) 
                {
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        Console.Write(reader[i].ToString());
                        if (i < reader.FieldCount - 1)
                        {
                            Console.Write(", ");
                        }
                    }
                    Console.WriteLine();
                }
            }
        }

        private static bool TryConnect()
        {
            GLogger.LogYellow("CONN", "RDS", "Connecting to RDS");
            if(conn !=null && conn.State == ConnectionState.Open)
            {
                return true;
            }

            try
            {
                conn = new MySqlConnection(connectionString);
                conn.Open();
                GLogger.LogGreen("SUCCESS", "RDS", "Connected to RDS!");
                return true;
            }
            catch(Exception e) 
            {
                GLogger.LogRed("ERR", "RDS", $"Failed to connect: {e}");
                return false;
            }
        }

        public static void CloseConnection()
        {
            GLogger.LogRed("Conn", "RDS", "Close RDS Connection");
            if(conn != null && conn.State == ConnectionState.Open)
            {
                conn.Close();
                GLogger.LogGreen("info", "RDS", "Connection closed");
            }
        }

        public class Auth
        {
            public static void InsertNewOAuthClient(Model.OAuthClient client)
            {
                GLogger.LogYellow("RDS-AUTH", "RDS", $"Create new OAuth client: {client}");
                string query = @"
                                INSERT INTO `Guardian`.`AuthDB`
                                (clientId, clientSecret, clientName, granttypes, clientStatus, businessCode, isActive)
                                VALUES
                                (@ClientId, @ClientSecret, @ClientName, @GrantTypes, @ClientStatus, @BusinessCode, @IsActive)
                                ";
                bool connected = RDS.TryConnect();
                if(connected) 
                {
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);

                    command.Parameters.AddWithValue("@ClientId", client.clientID);
                    command.Parameters.AddWithValue("@ClientSecret", client.clientSecret);
                    command.Parameters.AddWithValue("@ClientName", client.clientName);
                    command.Parameters.AddWithValue("@GrantTypes", client.grantTypes);
                    command.Parameters.AddWithValue("@ClientStatus", client.clientStatus);
                    command.Parameters.AddWithValue("@BusinessCode", client.businessCode);
                    command.Parameters.AddWithValue("@IsActive", client.isActive);

                    int result = command.ExecuteNonQuery();

                    if(result > 0)
                    {
                        GLogger.LogGreen("SUCCESS", "RDS-CRUD", $"Insert {client.clientID} successfully!");
                    }
                    else
                    {
                        GLogger.LogRed("ERR", "RDS-CRUD", $"Failed to Insert {client.clientID}");
                    }
                }
            }

            public static bool ValidateOAuthClient(string clientID, string clientSecret)
            {
                GLogger.LogYellow("RDS-Auth", "Validate", $"Validate OAuth client for: {clientID}");
                string query = "SELECT clientSecret " +
                               "FROM AuthDB " +
                               "WHERE clientID = @ClientId LIMIT 1";

                bool connected = RDS.TryConnect();
                if (connected) 
                {
                    GLogger.Log("RDS-VALIDATE-CLIENT", $"Start validate client: {clientID}");
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);
                    command.Parameters.AddWithValue("@ClientId", clientID);

                    string? querySecret = command.ExecuteScalar() as string;

                    if(querySecret != null && querySecret == clientSecret)
                    {
                        GLogger.LogGreen("SUCCESS", "RDS-VALIDATE-CLIENT", $"Validate OAuth client success! {clientID}");
                        return true;
                    }
                    else
                    {
                        GLogger.LogRed("INVALID", "RDS-VALIDATE-CLIENT", $"Failed to validate {clientID}");
                        return false;
                    }
                }
                else
                {
                    GLogger.LogRed("ERR", "RDS-CONN", "Failed to connect to RDS, ABORT validate client action");
                    return false;
                }
            }

            public static KeyValuePair<bool, bool> CheckClientHasLiveToken(string clientId)
            {
                GLogger.LogYellow("RDS-Auth", "LiveToken", $"Checking client has live token, for client: {clientId}");
                string query = @"SELECT accessToken
                               FROM AccessToken
                               WHERE associatedClient = @ClientId 
                                    AND expirationAt > NOW()
                               LIMIT 1";

                bool connected = RDS.TryConnect();

                if (connected) 
                {
                    GLogger.Log("RDS-VALIDATE-AccessToken", $"Start validate client: {clientId}");
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);
                    command.Parameters.AddWithValue("@ClientId", clientId);

                    using(MySqlDataReader reader = command.ExecuteReader()) 
                    {
                        if(reader.Read()) 
                        {
                            GLogger.Log("Check Existing AccessToken", "Found");
                            return new KeyValuePair<bool, bool>(true, true);
                        }
                        else
                        {
                            GLogger.Log("Check Existing AccessToken", "Not Found");
                            return new KeyValuePair<bool, bool>(true, false);
                        }
                    }
                }
                else
                {
                    GLogger.LogRed("ERROR", "Eheck Existing AccessToken", "Connection Failed");
                    return new KeyValuePair<bool, bool>(false, false); 
                }
            }

            public static void SaveNewAccessToken(Model.AccessToken accessToken)
            {
                GLogger.LogYellow("RDS-AUTH", "access token", $"Preparing create access token: {accessToken}");
                string query = @"
                                INSERT INTO `Guardian`.`AccessToken`
                                (accessToken, ssoUsed, isActive, isSSO, createdAt, expirationAt, expirationDuration, scopes, state, associatedClient, issuer, refreshToken)
                                VALUES
                                (@accessToken, @ssoUsed, @isActive, @isSSO, @createdAt, @expirationAt, @expirationDuration, @scopes, @state, @associatedClient, @issuer, @refreshToken)
                                ";
                bool connected = RDS.TryConnect();
                if (connected)
                {
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);

                    command.Parameters.AddWithValue("@accessToken", accessToken.value);
                    command.Parameters.AddWithValue("@ssoUsed", accessToken.ssoUsed);
                    command.Parameters.AddWithValue("@isActive", accessToken.isActive);
                    command.Parameters.AddWithValue("@isSSO", accessToken.isSSO);
                    command.Parameters.AddWithValue("@createdAt", accessToken.createdAt);
                    command.Parameters.AddWithValue("@expirationAt", accessToken.expirationAt);
                    command.Parameters.AddWithValue("@expirationDuration", accessToken.expirationDuration);
                    command.Parameters.AddWithValue("@scopes", accessToken.scopes);
                    command.Parameters.AddWithValue("@state", accessToken.state);
                    command.Parameters.AddWithValue("@associatedClient", accessToken.associatedClient);
                    command.Parameters.AddWithValue("@issuer", accessToken.issuer);
                    command.Parameters.AddWithValue("@refreshToken", accessToken.refreshToken);

                    int result = command.ExecuteNonQuery();

                    if (result > 0)
                    {
                        GLogger.LogGreen("SUCCESS", "RDS-AccessToken", $"Insert {accessToken.associatedClient}'s token: {accessToken.value} successfully!");
                    }
                    else
                    {
                        GLogger.LogRed("ERR", "RDS-CRUD", $"Failed to Insert {accessToken.associatedClient}'s token: {accessToken.value}");
                    }
                }
            }

            public static void SaveNewRefreshToken(Model.RefreshToken refreshToken)
            {
                GLogger.LogYellow("RDS-AUTH", "refresh token", $"Preparing create refresh token: {refreshToken}");
                string query = @"
                                INSERT INTO `Guardian`.`RefreshToken`
                                (value, isActive, createdAt, expirationAt, expirationDuration, associatedClient, issuer, lastAssociateAccessToken)
                                VALUES
                                (@value, @isActive, @createdAt, @expirationAt, @expirationDuration, @associatedClient, @issuer, @lastAssociateAccessToken)
                                ";
                bool connected = RDS.TryConnect();
                if (connected)
                {
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);

                    command.Parameters.AddWithValue("@value", refreshToken.value);
                    command.Parameters.AddWithValue("@isActive", refreshToken.isActive);
                    command.Parameters.AddWithValue("@createdAt", refreshToken.createdAt);
                    command.Parameters.AddWithValue("@expirationAt", refreshToken.expirationAt);
                    command.Parameters.AddWithValue("@expirationDuration", refreshToken.expirationDuration);
                    command.Parameters.AddWithValue("@associatedClient", refreshToken.associatedClient);
                    command.Parameters.AddWithValue("@issuer", refreshToken.issuer);
                    command.Parameters.AddWithValue("@lastAssociateAccessToken", refreshToken.lastAssociatedAccessToken);

                    int result = command.ExecuteNonQuery();

                    if (result > 0)
                    {
                        GLogger.LogGreen("SUCCESS", "RDS-AccessToken", $"Insert {refreshToken.associatedClient}'s token: {refreshToken.value} successfully!");
                    }
                    else
                    {
                        GLogger.LogRed("ERR", "RDS-CRUD", $"Failed to Insert {refreshToken.associatedClient}'s token: {refreshToken.value}");
                    }
                }
            }

            public static async Task<Model.AccessToken> RenewAccessToken (string clientId) 
            {
                GLogger.LogYellow("RDS-AUTH", "access token", $"Preparing renew access token for client: {clientId}");
                string query = "SELECT accessToken, state, ssoUsed, isSSO, scopes, refreshToken, issuer " +
                               "FROM AccessToken " +
                               "WHERE associatedClient = @ClientId " +
                                      "AND expirationAt > NOW()" +
                               "LIMIT 1";
                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-AccessToken", $"Start indexing token for client: {clientId}");
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);
                    command.Parameters.AddWithValue("@ClientId", clientId);

                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        if(reader.Read())
                        {
                            string? accessTokenValue = reader["accessToken"] as string;
                            string? state = reader["state"] as string;
                            bool ssoUsed = reader.GetBoolean(reader.GetOrdinal("ssoUsed"));
                            bool isSSO = reader.GetBoolean(reader.GetOrdinal("isSSO"));
                            string? scopes = reader["scopes"] as string;
                            string? refreshToken = reader["refreshToken"] as string;
                            string? issuer = reader["issuer"] as string;

                            if (state != GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_REVOKED ||
                               state != GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_SUSPENDED ||
                               state != GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_EXPIRED ||
                               state != GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_LOCKED)
                            {
                                RDS.CloseConnection();
                                RDS.TryConnect();
                                string refreshTokenQuery = @"
                                                            UPDATE AccessToken
                                                            SET state = @NewState, createdAt = @NewCreatedAt, expirationAt = @NewExpiredAt
                                                            WHERE associatedClient = @ClientId
                                                             AND accessToken = @AccessTokenVal";

                                MySqlCommand updateCommand = new MySqlCommand(refreshTokenQuery, RDS.conn);
                                updateCommand.Parameters.AddWithValue("@NewState", GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_REFRESHED);
                                updateCommand.Parameters.AddWithValue("@NewCreatedAt", DateTime.UtcNow);
                                updateCommand.Parameters.AddWithValue("@NewExpiredAt", Services.Auth.CalculateExpirationDateTime(DateTime.UtcNow, (int)GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_10M!));
                                updateCommand.Parameters.AddWithValue("@ClientId", clientId);
                                updateCommand.Parameters.AddWithValue("AccessTokenVal", accessTokenValue);

                                int rowsAffected = updateCommand.ExecuteNonQuery();
                                if(rowsAffected > 0)
                                {

                                    GLogger.LogGreen("SUCCESS", "RDS-AccessToken", $"{clientId} token been refreshed with new expiration time!");
                                    Model.AccessToken refreshedToken = new Model.AccessToken();
                                    refreshedToken.value = accessTokenValue;
                                    refreshedToken.isSSO = isSSO;
                                    refreshedToken.ssoUsed = ssoUsed;
                                    refreshedToken.scopes = scopes;
                                    refreshedToken.issuer = issuer;
                                    refreshedToken.refreshToken = refreshToken;
                                    refreshedToken.expirationAt = Services.Auth.CalculateExpirationDateTime(DateTime.UtcNow, (int)GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_10M!);
                                    refreshedToken.associatedClient = clientId;

                                    return refreshedToken;
                                }
                                else
                                {
                                    GLogger.LogRed("Error", "RDS-AccessToken", "Failed to refresh token, error at failed to update the DB");
                                }
                            }
                            else if(state == GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_REVOKED ||
                                    state == GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_EXPIRED)
                            {
                                Model.AccessToken accessTokenCandidate = new Model.AccessToken();
                                accessTokenCandidate.value = await Services.AWS.KMS.GetAccessToken();
                                accessTokenCandidate.isSSO = isSSO;
                                accessTokenCandidate.ssoUsed = ssoUsed;
                                accessTokenCandidate.scopes = scopes;
                                accessTokenCandidate.issuer = issuer;
                                accessTokenCandidate.refreshToken = refreshToken;
                                accessTokenCandidate.createdAt = DateTime.UtcNow;
                                accessTokenCandidate.expirationAt = Services.Auth.CalculateExpirationDateTime(DateTime.UtcNow, (int)GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_10M!);
                                accessTokenCandidate.expirationDuration = (int)GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_10M;
                                accessTokenCandidate.isActive = true;
                                accessTokenCandidate.state = GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_ISSUED;
                                accessTokenCandidate.associatedClient = clientId;

                                SaveNewAccessToken(accessTokenCandidate);
                                GLogger.LogGreen("SUCCESS", "RDS-AccessToken", $"New Token Issued to {clientId}, and saved to DB");
                                return accessTokenCandidate;
                            }
                            else
                            {
                                GLogger.LogYellow("WARN", "RDS-AccessToken", "Illegal token status found, Guardian won't refresh/generate new token, please unlock account");
                                return Util.Data.DUMMY_VOID_TOKEN(clientId);
                            }
                        }                      
                    }
                    
                }
                else
                {
                    GLogger.LogRed("ERR", "RDS-CONN", "Failed to connect to RDS, ABORT validate client action");
                    return Util.Data.DUMMY_VOID_TOKEN(clientId); ;
                }
                return Util.Data.DUMMY_VOID_TOKEN(clientId);
            }

            public static Model.AccessToken GetAccessTokenByTokenValue(string tokenValue)
            {
                GLogger.LogYellow("RDS-Auth", "GetTokenObj", $"get access token object from value: {tokenValue}");
                DeepCleanExpiredAccessToken();
                Model.AccessToken accessToken = new Model.AccessToken();
                string query = "SELECT accessToken, state, ssoUsed, isSSO, isActive, expirationAt, associatedClient, scopes, issuer " +
                               "FROM AccessToken " +
                               "WHERE accessToken = @TokenValue " +
                               "LIMIT 1";
                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-AccessToken", $"Start retro token for token: {tokenValue}");
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);
                    command.Parameters.AddWithValue("@TokenValue", tokenValue);

                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string? accessTokenValue = reader["accessToken"] as string;
                            string? state = reader["state"] as string;
                            bool ssoUsed = reader.GetBoolean(reader.GetOrdinal("ssoUsed"));
                            bool isSSO = reader.GetBoolean(reader.GetOrdinal("isSSO"));
                            bool isActive = reader.GetBoolean(reader.GetOrdinal("isActive"));
                            string? scopes = reader["scopes"] as string;
                            DateTime? expirationAt = reader.GetDateTime(reader.GetOrdinal("expirationAt"));
                            string? associatedClient = reader["associatedClient"] as string;
                            string? issuer = reader["issuer"] as string;

                            accessToken.value = accessTokenValue;
                            accessToken.state = state;
                            accessToken.ssoUsed = ssoUsed;
                            accessToken.isSSO = isSSO;
                            accessToken.isActive = isActive;
                            accessToken.scopes = scopes;
                            accessToken.expirationAt = (DateTime)expirationAt;
                            accessToken.associatedClient = associatedClient;
                            accessToken.issuer = issuer;

                            return accessToken;
                        }
                    }
                }
                return null;
            }

            public static Model.RefreshToken GetRefreshTokenByTokenValue(string tokenValue)
            {
                GLogger.LogYellow("RDS-Auth", "GetTokenObj", $"get refresh token object from value: {tokenValue}");
                Model.RefreshToken refreshToken = new Model.RefreshToken();
                string query = "SELECT value, isActive, expirationAt, associatedClient, issuer " +
                               "FROM RefreshToken " +
                               "WHERE value = @TokenValue " +
                               "LIMIT 1";
                bool connected = RDS.TryConnect();  
                if (connected)
                {
                    GLogger.Log("RDS-RefreshToken", $"Start retro token for token: {tokenValue}");
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);
                    command.Parameters.AddWithValue("@TokenValue", tokenValue);

                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string? value = reader["value"] as string;
                            bool isActive = reader.GetBoolean(reader.GetOrdinal("isActive"));
                            DateTime? expirationAt = reader.GetDateTime(reader.GetOrdinal("expirationAt"));
                            string? associatedClient = reader["associatedClient"] as string;
                            string? issuer = reader["issuer"] as string;

                            refreshToken.value = value;
                            refreshToken.isActive = isActive;
                            refreshToken.expirationAt = (DateTime)expirationAt;
                            refreshToken.associatedClient = associatedClient;
                            refreshToken.issuer = issuer;

                            return refreshToken;
                        }
                    }
                }
                GLogger.LogYellow("WARN", "RDS-RefreshToken", $"Failed to find token {tokenValue}!");
                return null;
            }

            public static bool CheckAndValidateRefreshtokenFromClient(string clientId)
            {
                GLogger.LogYellow("RDS-Auth", "CheckRefreshToken", $"Check and Validate Refresh token from client: {clientId}");
                DeepCleanExpiredRefreshToken();
                string getValidTokenQuery = "SELECT value, isActive, expirationAt, associatedClient, lastAssociateAccessToken " +
                               "FROM RefreshToken " +
                               "WHERE associatedClient = @ClientId " +
                                      "AND expirationAt > NOW() " +
                                      "AND isActive = true " +
                               "LIMIT 1";

                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-RefreshToken", $"Start indexing refresh token for client: {clientId}");
                    MySqlCommand command = new MySqlCommand(getValidTokenQuery, RDS.conn);
                    command.Parameters.AddWithValue("@ClientId", clientId);

                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        if(reader.Read()) 
                        {
                            GLogger.Log("RDS-Refreshtoken", "Found active refresh token!");
                            return true;
                        }
                    }
                }
                return false;
            }
            public static string GetRefreshTokenValueFromClientId(string clientId)
            {
                GLogger.LogYellow("RDS-AUTH", "RefreshAccessToken", $"Refresh access token from the client: {clientId}");
                string query = @"SELECT value FROM RefreshToken WHERE associatedClient = @ClientId LIMIT 1";
                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-RefreshToken", $"Start get refresh token value for client: {clientId}");
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);
                    command.Parameters.AddWithValue("@ClientId", clientId);

                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string? refreshTokenValue = reader["value"] as string;
                            return refreshTokenValue!;
                        }
                    }
                }
                GLogger.LogRed("ERR", "RDS-GetRefreshToken", $"Failed to retrieve refresh token value for client {clientId}");
                return "error";
            }

            public static void DeepCleanExpiredRefreshToken()
            {
                GLogger.LogYellow("RDS", "Refresh-reset", "Deep Refresh Refresh Token");
                string updateQuery = "UPDATE RefreshToken SET isActive = false " +
                                     "WHERE isActive = true " +
                                     "AND expirationAt < NOW()";

                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-RefreshToken", "Start updating expired refresh tokens to inactive");

                    MySqlCommand updateCommand = new MySqlCommand(updateQuery, RDS.conn);
                    int rowsAffected = updateCommand.ExecuteNonQuery();

                    GLogger.Log("RDS-RefreshToken", $"Updated {rowsAffected} tokens to inactive");
                }
            }

            public static void DeepCleanExpiredAccessToken()
            {
                GLogger.LogYellow("RDS", "Refresh-reset", "Deep Refresh access Token");
                string updateQuery = "UPDATE AccessToken SET isActive = false " +
                                     "WHERE isActive = true AND (expirationAt < NOW() " +
                                     "OR state = 'SUSPENDED' " +
                                     "OR state = 'EXPIRED' " +
                                     "OR state = 'REVOKED' " +
                                     "OR state = 'LOCKED')";

                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-accessToken", "Start updating expired access tokens to inactive");

                    MySqlCommand updateCommand = new MySqlCommand(updateQuery, RDS.conn);
                    int rowsAffected = updateCommand.ExecuteNonQuery();

                    GLogger.Log("RDS-accessToken", $"Updated {rowsAffected} tokens to inactive");
                }
            }

            public static async Task<Model.AccessToken> CreateNewAccessTokenAttachRefreshToken(string clientId)
            {
                GLogger.LogYellow("RDS-Auth", "Create", $"Create new Access Token Linked with RefreshToken for {clientId}");
                DeepCleanExpiredAccessToken();
                string accessTokenValue = await Services.AWS.KMS.GetAccessToken();
                string newRefreshTokenValue = await Services.AWS.KMS.GetRefreshToken();

                //needs to check if current client has a valid refresh token.
                bool liveRefreshTokenExist = CheckAndValidateRefreshtokenFromClient(clientId);
                if (liveRefreshTokenExist) 
                {
                    string currentRefreshTokenValue = GetRefreshTokenValueFromClientId(clientId);
                    Model.AccessToken accessToken = new Model.AccessToken();
                    accessToken.value = accessTokenValue;
                    accessToken.isSSO = false;
                    accessToken.ssoUsed = false;
                    accessToken.scopes = "currently no scopes";
                    accessToken.issuer = "Guardian";
                    accessToken.refreshToken = currentRefreshTokenValue;
                    accessToken.createdAt = DateTime.UtcNow;
                    accessToken.expirationAt = Services.Auth.CalculateExpirationDateTime(DateTime.UtcNow, (int)GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_10M!);
                    accessToken.expirationDuration = (int)GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_10M;
                    accessToken.isActive = true;
                    accessToken.state = GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_ISSUED;
                    accessToken.associatedClient = clientId;
                    SaveNewAccessToken(accessToken);

                    return accessToken;

                }
                else
                {
                    Model.RefreshToken newRefreshToken = new Model.RefreshToken();
                    newRefreshToken.value = newRefreshTokenValue;
                    newRefreshToken.isActive = true;
                    newRefreshToken.createdAt = DateTime.UtcNow;
                    newRefreshToken.expirationDuration = (int)GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_30D!;
                    newRefreshToken.expirationAt = Services.Auth.CalculateExpirationDateTime(DateTime.UtcNow, (int)GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_30D!);
                    newRefreshToken.associatedClient = clientId;
                    newRefreshToken.issuer = "Guardian";
                    newRefreshToken.lastAssociatedAccessToken = accessTokenValue;
                    SaveNewRefreshToken(newRefreshToken);

                    Model.AccessToken accessToken = new Model.AccessToken();
                    accessToken.value = accessTokenValue;
                    accessToken.isSSO = false;
                    accessToken.ssoUsed = false;
                    accessToken.scopes = "currently no scopes";
                    accessToken.issuer = "Guardian";
                    accessToken.refreshToken = newRefreshTokenValue;
                    accessToken.createdAt = DateTime.UtcNow;
                    accessToken.expirationAt = Services.Auth.CalculateExpirationDateTime(DateTime.UtcNow, (int)GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_10M!);
                    accessToken.expirationDuration = (int)GUARDIAN_CONFIGS.OAuth.TOKEN_LIFE_SPAN_10M;
                    accessToken.isActive = true;
                    accessToken.state = GUARDIAN_CONFIGS.OAuth.TOKEN_STATE_ISSUED;
                    accessToken.associatedClient = clientId;
                    SaveNewAccessToken(accessToken);

                    return accessToken;
                }
                
            }

            public static bool RevokeAccessTokenByTokenValue(string accessTokenVal, string clientId)
            {
                GLogger.LogYellow("RDS-Auth", "Revoke", $"Revoke token: {accessTokenVal} for client: {clientId}");
                string updateQuery = @"UPDATE AccessToken SET isActive = false, state = 'REVOKED' 
                                     WHERE accessToken = @tokenValue 
                                     AND associatedClient = @ClientId";

                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-accessToken", "Start updating expired access tokens to inactive");

                    MySqlCommand updateCommand = new MySqlCommand(updateQuery, RDS.conn);
                    updateCommand.Parameters.AddWithValue("@tokenValue", accessTokenVal);
                    updateCommand.Parameters.AddWithValue("@ClientId", clientId);
                    int rowsAffected = updateCommand.ExecuteNonQuery();

                    if (rowsAffected > 0) 
                    {
                        GLogger.LogYellow("Success", "RevokeToken", "AccessToken been successfully revoked!");
                        return true;
                    }
                    else
                    {
                        GLogger.LogYellow("ERR", "RevokeToken", "Can't locate this token!");
                        return false;
                    }
                }
                return false;
            }

            public static bool RevokeRefreshTokenByTokenValue(string refreshTokenVal, string clientId)
            {
                GLogger.LogYellow("RDS-AUTH", "RevokeToken", $"Revoke Refreshtoken: {refreshTokenVal} for client: {clientId}");
                string updateQuery = @"UPDATE RefreshToken SET isActive = false 
                                     WHERE value = @TokenValue 
                                     AND associatedClient = @ClientId";

                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-accessToken", "Start updating expired refresh token to inactive");

                    MySqlCommand updateCommand = new MySqlCommand(updateQuery, RDS.conn);
                    updateCommand.Parameters.AddWithValue("@TokenValue", refreshTokenVal);
                    updateCommand.Parameters.AddWithValue("@ClientId", clientId);
                    int rowsAffected = updateCommand.ExecuteNonQuery();

                    if (rowsAffected > 0)
                    {
                        GLogger.LogYellow("Success", "RevokeToken", "RefreshToken been successfully revoked!");
                        return true;
                    }
                    else
                    {
                        GLogger.LogYellow("ERR", "RevokeToken", "Can't locate this token!");
                        return false;
                    }
                }
                return false;
            }
        }

        public class Validation
        {
            public static bool ValidateCard(string SN)
            {
                GLogger.LogYellow("VALIDATE", "CARD", $"Validate card: {SN}");
                RDS.ChangeToIssuerDB();

                string query = "SELECT SN, isValid " +
                               "FROM Issuer.Cards " +
                               "WHERE SN = @SN " +
                                      "AND isValid = true " +
                               "LIMIT 1";

                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-ValidateCard", $"Start Validate Card: {SN}");
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);

                    command.Parameters.AddWithValue("@SN", SN);
                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            GLogger.Log("RDS-ValidateCard", "Found valid card");
                            return true;
                        }
                    }
                }
                return false;
            }
        }

        public class Journal
        {
            public static void SaveJournal (Model.Journal journal)
            {
                GLogger.LogYellow("JOURNAL", "Create", "Start Creating journal and save");
                string query = @"
                                INSERT INTO `Guardian`.`Journal`
                                (transactionCreateTime, recentUpdateTime, cardSN, associateClient, guardianCodeHash, value, status)
                                VALUES
                                (@transactionCreateTime, @recentUpdateTime, @cardSN, @associateClient, @guardianCodeHash, @value, @status)
                                ";
                bool connected = RDS.TryConnect();
                if (connected)
                {
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);

                    command.Parameters.AddWithValue("@transactionCreateTime", journal.transactionCreateTime);
                    command.Parameters.AddWithValue("@recentUpdateTime", journal.recentUpdateTime);
                    command.Parameters.AddWithValue("@cardSN", journal.cardSN);
                    command.Parameters.AddWithValue("@associateClient", journal.associateClient);
                    command.Parameters.AddWithValue("@guardianCodeHash", journal.guardianCodeHash);
                    command.Parameters.AddWithValue("@value", journal.value);
                    command.Parameters.AddWithValue("@status", journal.status);

                    int result = command.ExecuteNonQuery();

                    if (result > 0)
                    {
                        GLogger.LogGreen("SUCCESS", "RDS-Journal", $"Insert Journal successfully!");
                    }
                    else
                    {
                        GLogger.LogRed("ERR", "RDS-CRUD-Journal", $"Failed to Insert journal");
                    }
                }
            }

            public static bool CheckJournal(Model.Journal journal)
            {
                GLogger.LogYellow("JOURNAL", "Validate", $"Validate journal for card: {journal.cardSN}");
                string cardSN = journal.cardSN!;
                string assoiciateClient = journal.associateClient!;
                string guardianCodeHash = journal.guardianCodeHash!;
                string status = journal.status!;

                string query = @"SELECT journalID
                               FROM Journal
                               WHERE cardSN = @cardSN
                               AND associateClient = @assoiciateClient
                               AND guardianCodeHash = @guardianCodeHash
                               AND status = @status
                               LIMIT 1";

                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-VERYFY-JOURNAL", $"Start validate Journal");
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);
                    command.Parameters.AddWithValue("@cardSN", cardSN);
                    command.Parameters.AddWithValue("@assoiciateClient", assoiciateClient);
                    command.Parameters.AddWithValue("@guardianCodeHash", guardianCodeHash);
                    command.Parameters.AddWithValue("@status", status);

                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            GLogger.Log("RDS-ValidateJournal", "Validate Success");
                            return true;
                        }
                    }
                }               
                GLogger.LogRed("ERR", "RDS-CONN", "Failed to connect to RDS, ABORT validate journal action");
                return false;
                
            }

            public static bool CheckExistingJournal(Model.Journal journal)
            {
                GLogger.LogYellow("JOURNAL", "Validate", $"Validate existing Journal for card: {journal.cardSN}");
                string cardSN = journal.cardSN!;

                string query = @"SELECT journalID
                               FROM Journal
                               WHERE cardSN = @cardSN
                               LIMIT 1";

                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-VERYFY-JOURNAL", $"Start validate Journal");
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);
                    command.Parameters.AddWithValue("@cardSN", cardSN);

                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            GLogger.Log("RDS-CheckExistJournal", "Found");
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }
                }
                GLogger.LogRed("ERR", "RDS-CONN", "Failed to connect to RDS, ABORT check journal action");
                return true;

            }

            public static string GetGuardianHashFromCardSN(string cardSN)
            {
                GLogger.LogYellow("GuardianCode", "GetHashing", $"Get Guardian hashed code for card: {cardSN}");
                string query = @"SELECT guardianCodeHash
                               FROM Journal
                               WHERE cardSN = @cardSN
                               AND status = 'REDEEM PENDING'
                               LIMIT 1";

                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-VERYFY-JOURNAL", $"Start validate Journal");
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);
                    command.Parameters.AddWithValue("@cardSN", cardSN);

                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            GLogger.Log("RDS-GET Hash", "Found");
                            string? guardianCodeHash = reader["guardianCodeHash"] as string;
                            return guardianCodeHash!;
                        }
                        else
                        {
                            return "error";
                        }
                    }
                }
                
                GLogger.LogRed("ERR", "RDS-CONN", "Failed to connect to RDS, ABORT check journal action");
                return "error";
            }

            public static void FailedGuardianCodeDeductRetry(string cardSN)
            {
                GLogger.LogRed("Redeem", "Faild", "Perform deduct retry by one");
                string query = @"UPDATE Journal
                               SET retryTime = retryTime - 1
                               WHERE cardSN = @cardSN
                               AND status = 'REDEEM PENDING'";


                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-deduct retry", $"Dedcuted 1 retry for card {cardSN}");

                    MySqlCommand updateCommand = new MySqlCommand(query, RDS.conn);
                    updateCommand.Parameters.AddWithValue("@cardSN", cardSN);
                    int rowsAffected = updateCommand.ExecuteNonQuery();

                    GLogger.Log("RDS-deductRetry", $"Updated {rowsAffected} to the record");
                }
            }

            public static void LockCard(string cardSN) 
            {
                GLogger.LogRed("Redeem", "Lock", $"Locking card for card Id:{cardSN}");
                string query = @"UPDATE Journal
                               SET status = 'LOCKED'
                               WHERE cardSN = @cardSN";


                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-lockCard", $"{cardSN} been locked");

                    MySqlCommand updateCommand = new MySqlCommand(query, RDS.conn);
                    updateCommand.Parameters.AddWithValue("@cardSN", cardSN);
                    int rowsAffected = updateCommand.ExecuteNonQuery();

                    GLogger.Log("RDS-lockCard", $"Updated {rowsAffected} to the record");
                }
            }

            public static void StatusChangeToRedeemed(string cardSN) 
            {

                GLogger.LogYellow("CARD", "STATUS", $"Change card {cardSN} status to REDEEMED");
                string query = @"UPDATE Journal
                               SET status = 'REDEEMED'
                               WHERE cardSN = @cardSN";


                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-RedeemCard", $"{cardSN} been Redeemed");

                    MySqlCommand updateCommand = new MySqlCommand(query, RDS.conn);
                    updateCommand.Parameters.AddWithValue("@cardSN", cardSN);
                    int rowsAffected = updateCommand.ExecuteNonQuery();

                    GLogger.Log("RDS-RedeemCard", $"Updated {rowsAffected} to the record");
                }
            }

            public static int CheckLeftRetryValue(string cardSN) 
            {
                GLogger.LogGreen("CARD", "Check-retry", $"Checking retry quantity for card: {cardSN}");
                string query = @"SELECT retryTime
                               FROM Journal
                               WHERE cardSN = @cardSN
                               LIMIT 1";

                bool connected = RDS.TryConnect();
                if (connected)
                {
                    GLogger.Log("RDS-Check Retry", $"Start check for card {cardSN}");
                    MySqlCommand command = new MySqlCommand(query, RDS.conn);
                    command.Parameters.AddWithValue("@cardSN", cardSN);

                    using (MySqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            int retryTime = reader.GetInt32(reader.GetOrdinal("retryTime"));
                            GLogger.Log("RDS-GET-retryLeft", $"Found retry left: {retryTime}");
                            return retryTime;
                        }
                        else
                        {
                            return -1;
                        }
                    }
                }

                GLogger.LogRed("ERR", "RDS-CONN", "Failed to connect to RDS, ABORT check retryVal action");
                return -1;
            }

        }
    }
}

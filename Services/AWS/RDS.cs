using GuardianService.Configs;
using GuardianService.Model;
using GuardianService.Util;
using Microsoft.Extensions.Logging.Abstractions;
using MySql.Data.MySqlClient;
using System.Data;
using YamlDotNet.Serialization.NodeDeserializers;

namespace GuardianService.Services.AWS
{
    public class RDS
    {
        static string connectionString;
        private static MySqlConnection? conn = null;

        static RDS()
        {
            connectionString = $"Server={GUARDIAN_CONFIGS.RDS.SERVER}; " +
                               $"Database={GUARDIAN_CONFIGS.RDS.DATABASE}; " +
                               $"UID={GUARDIAN_CONFIGS.RDS.USERNAME}; " +
                               $"password={GUARDIAN_CONFIGS.RDS.PASSWORD}; " +
                               $"Port={GUARDIAN_CONFIGS.RDS.PORT}; ";
        }
        public static bool CheckAWSRDSConnection()
        {
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

        private void CloseConnection()
        {
            if(conn != null && conn.State == ConnectionState.Open)
            {
                conn.Close();
                GLogger.LogGreen("info", "RDS", "Connection closed");
            }
        }

        public class Auth
        {
            public static void InsertNewOAuthClient(OAuthClient client)
            {
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
                string query = "SELECT clientSecret FROM AuthDB WHERE clientID = @ClientId LIMIT 1";

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
        }
    }
}

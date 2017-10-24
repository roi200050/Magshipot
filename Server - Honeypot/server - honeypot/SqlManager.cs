using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MySql.Data.MySqlClient;
using System.Threading.Tasks;
using System.Net;

namespace Server___HoneyPot
{
    class SqlManager
    {
        //String For the connection with the server
        private const string connStr = "Server=localhost;Port=3306;Database=honeypot;UId=root;Password=318443041;";

        //Commands For Creation Tables
        private const string CREATE_CONNECTIONS_TABLE = "CREATE TABLE Connections (Date DATE, Address TEXT, AttackedPorts TEXT, Country TEXT, TypesOfAttacks TEXT, NetworkDistance INT, OS TEXT, OpenPorts TEXT, JavascriptOS TEXT, Browser TEXT, BrowserVersion TEXT, BrowserLenguage TEXT, UsingCookies TEXT)";
        private const string CREATE_ATTACKS_TABLE = "CREATE TABLE Attacks (TypeOfAttack TEXT, Date DATE, Duration TEXT, Address TEXT)";
        private const string CREATE_HONEYPOTS_TABLE = "CREATE TABLE Honeypots (ID INT, Address TEXT)";
        private const string CREATE_PROCESSES_TABLE = "CREATE TABLE Processes (ID INT, Name TEXT, Addresses TEXT)";
        
        //Commands For Insertion To Tables
        private const string INSERT_CONNECTIONS_TABLE = "INSERT INTO Connections VALUES (@Date, @Address, @AttackedPorts, @Country, @TypesOfAttacks, @NetworkDistance, @OS, @OpenPorts, @JavascriptOS, @Browser, @BrowserVersion, @BrowserLenguage, @UsingCookies)";
        private const string INSERT_ATTACKS_TABLE = "INSERT INTO Attacks VALUES (@TypeOfAttack, @Date, @Duration, @Address)";
        private const string INSERT_HONEYPOTS_TABLE = "INSERT INTO Honeypots VALUES (@ID, @Address)";
        private const string INSERT_PROCESSES_TABLE = "INSERT INTO Processes VALUES (@ID, @Name, @Addresses)";

        private const string INSERT_CONNECTIONS_TABLE_WHERE = "UPDATE Connections SET JavascriptOS = @JavascriptOS, Browser = @Browser, BrowserVersion = @BrowserVersion, BrowserLenguage = @BrowserLenguage, UsingCookies = @UsingCookies WHERE Address = @IP";

        private MySqlConnection Sql_Server;
        private MySqlCommand Command;
        private MySqlDataReader Reader;
        private static int HoneypotCount = 0;

        private void ExeuteCommand(bool IsResponse)
        {
            try
            {
                if (IsResponse)
                    Reader = Command.ExecuteReader();
                else
                    Command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public SqlManager()
        {
            //connect to the server
            Sql_Server = new MySqlConnection(connStr);
            Sql_Server.Open();

            //open tables:

            //open Connections table
            Command = new MySqlCommand(CREATE_CONNECTIONS_TABLE, Sql_Server);
            ExeuteCommand(false);

            //open Attacks table
            Command = new MySqlCommand(CREATE_ATTACKS_TABLE, Sql_Server);
            ExeuteCommand(false);

            //open Honeypots table
            Command = new MySqlCommand(CREATE_HONEYPOTS_TABLE, Sql_Server);
            ExeuteCommand(false);

            //open Processes table
            Command = new MySqlCommand(CREATE_PROCESSES_TABLE, Sql_Server);
            ExeuteCommand(false);
        }

        public void Insert_ProcessInfo(string info)
        {
            var arr = info.Split('|');
            try
            {
                //Place in Processes Table
                Command = new MySqlCommand(INSERT_PROCESSES_TABLE, Sql_Server);

                Command.Parameters.Add(new MySqlParameter("Name", arr[0]));
                Command.Parameters.Add(new MySqlParameter("ID", arr[1]));
                Command.Parameters.Add(new MySqlParameter("Addresses", arr[2]));

                ExeuteCommand(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public void Insert_CollectedInfo(CollectedInfo info)
        {
            try
            {
                //Place in Connections Table
                Command = new MySqlCommand(INSERT_CONNECTIONS_TABLE, Sql_Server);

                Command.Parameters.Add(new MySqlParameter("Address", info.IP_Address.ToString()));
                Command.Parameters.Add(new MySqlParameter("OpenPorts", string.Join(",", info.OpenPorts.ToArray())));
                Command.Parameters.Add(new MySqlParameter("OS", info.OS));
                Command.Parameters.Add(new MySqlParameter("Date", info.Date));
                if (info.Attacks == null)
                    Command.Parameters.Add(new MySqlParameter("TypesOfAttacks", "NULL"));
                else
                    Command.Parameters.Add(new MySqlParameter("TypesOfAttacks", string.Join(",", info.Attacks.ToArray())));
                if(info.AttackedPorts == null)
                    Command.Parameters.Add(new MySqlParameter("AttackedPorts", "NULL"));
                else
                    Command.Parameters.Add(new MySqlParameter("AttackedPorts", string.Join(",", info.AttackedPorts.ToArray())));
                Command.Parameters.Add(new MySqlParameter("Country", info.Country));
                Command.Parameters.Add(new MySqlParameter("NetworkDistance", info.NetworkDistance));
                Command.Parameters.Add(new MySqlParameter("JavascriptOS", ""));
                Command.Parameters.Add(new MySqlParameter("Browser", ""));
                Command.Parameters.Add(new MySqlParameter("BrowserVersion", ""));
                Command.Parameters.Add(new MySqlParameter("BrowserLenguage", ""));
                Command.Parameters.Add(new MySqlParameter("UsingCookies", ""));
                
                ExeuteCommand(false);

                //Place in Attacks Table
                if (info.Attacks != null)
                {
                    for (int i = 0; i < info.Attacks.Count; i++)
                    {
                        string date = info.AttacksPeriods[i].ToString();
                        Command = new MySqlCommand(INSERT_ATTACKS_TABLE, Sql_Server);

                        Command.Parameters.Add(new MySqlParameter("TypeOfAttack", info.Attacks[i]));
                        Command.Parameters.Add(new MySqlParameter("Date", info.Date));
                        Command.Parameters.Add(new MySqlParameter("Duration", info.AttacksPeriods[i].ToString()));
                        Command.Parameters.Add(new MySqlParameter("Address", info.IP_Address.ToString()));

                        ExeuteCommand(false);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public void InsertJavaScriptInfo(string addr, string JavascriptOS, string Browser, string BrowserVersion, string BrowserLenguage, string UsingCookies)
        {
            try
            {
                //Place in Honeypots Table
                Command = new MySqlCommand(INSERT_CONNECTIONS_TABLE_WHERE, Sql_Server);

                Command.Parameters.Add(new MySqlParameter("JavascriptOS", JavascriptOS));
                Command.Parameters.Add(new MySqlParameter("Browser", Browser));
                Command.Parameters.Add(new MySqlParameter("BrowserVersion", BrowserVersion));
                Command.Parameters.Add(new MySqlParameter("BrowserLenguage", BrowserLenguage));
                Command.Parameters.Add(new MySqlParameter("UsingCookies", UsingCookies));
                Command.Parameters.Add(new MySqlParameter("IP", addr));
                ExeuteCommand(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
        public void InsertNewHoneypot(IPAddress addr)
        {
            try
            {
                //Place in Honeypots Table
                Command = new MySqlCommand(INSERT_HONEYPOTS_TABLE, Sql_Server);

                Command.Parameters.Add(new MySqlParameter("Address", addr.ToString()));
                Command.Parameters.Add(new MySqlParameter("ID", HoneypotCount));
                ExeuteCommand(false);
                HoneypotCount++;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
        public int IsAttacker(string addr)
        {
            string cmd;
            
            cmd = "SELECT * FROM Connections WHERE Address='" + addr + "';";
            try
            {
                Command = new MySqlCommand(cmd, Sql_Server);
                ExeuteCommand(true);
                if (Reader.Read())
                {
                    if (Reader.GetString(4).CompareTo("NULL") == 0)//Connection
                        return 0;
                    else //Attacker
                        return 1;
                }
                else
                    return -1;//Not Connection and not Attacker
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return -1;
        }
    }
}

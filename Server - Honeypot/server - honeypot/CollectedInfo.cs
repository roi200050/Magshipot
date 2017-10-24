using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;

namespace Server___HoneyPot
{
    class CollectedInfo
    {
        public DateTime Date { get; set; }
        public IPAddress IP_Address { get; set; }
        public HashSet<int> AttackedPorts { get; set; }
        public string Country { get; set; }
        public List<string> Attacks { get; set; }
        public int NetworkDistance { get; set; }
        public string OS { get; set; }
        public List<int> OpenPorts { get; set; }
        public List<TimeSpan> AttacksPeriods { get; set; }

        public CollectedInfo(DateTime date, IPAddress ip,
                      HashSet<int> att_ports, string country, List<string> attacks,
                      int distance, string os, List<int> open_ports, List<TimeSpan> times)
        {
            this.Date = date;
            this.IP_Address = ip;
            this.AttackedPorts = att_ports;
            this.Country = country;
            this.Attacks = attacks;
            this.NetworkDistance = distance;
            this.OS = os;
            this.OpenPorts = open_ports;
            this.AttacksPeriods = times;
        }

        public CollectedInfo(List<string> args)
        {
            try
            {
                //this.Date = Convert.ToDateTime(args[0]);
                this.Date = DateTime.ParseExact(args[0], "dd/MM/yyyy HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
            }
            catch (Exception)
            {

                this.Date = DateTime.Now;
            }
            this.IP_Address = IPAddress.Parse(args[1]);

            //this.AttackedPorts = new HashSet<int>(args[2].Split(new char[] { ',' }).ToList().Select(s => Convert.ToInt32(s)).ToList());
            var string_hs = new HashSet<string>(args[2].Split(new char[] { ',' }).ToList());
            this.AttackedPorts = new HashSet<int>((from s in string_hs
                                                   where !string.IsNullOrEmpty(s)
                                                   select int.Parse(s)).ToList());
            this.Country = args[3];
            this.Attacks = args[4].Split(new char[] { ',' }).ToList();
            this.NetworkDistance = int.Parse(args[5]);
            this.OS = args[6];
            string_hs = new HashSet<string>(args[7].Split(new char[] { ',' }).ToList());
            if (string_hs.Count > 0)
            {
                this.OpenPorts = (from s in string_hs
                                  where !string.IsNullOrEmpty(s)
                                  select int.Parse(s)).ToList();
            }
            var temp_times = args[8].Split(new char[] { ',' }).ToList();        // not sure if this works
            TimeSpan time = TimeSpan.Zero;                                      
            this.AttacksPeriods = new List<TimeSpan>(from t in temp_times
                                                     where TimeSpan.TryParse(t, out time)
                                                     select time);
        }

        public override string ToString()
        {
            string info = "";
            info += "Date = " + Date.ToString();
            info += "\nip = " + IP_Address.ToString();
            info += "\nAttacked Ports = " + string.Join(",", AttackedPorts);
            info += "\nCountry = " + Country;
            if(Attacks != null)
                info += "\nAttacks = " + string.Join(",", Attacks);
            info += "\nNetwork Distance = " + NetworkDistance.ToString();
            info += "\nOperation System = " + OS;
            if(OpenPorts != null)
                info += "\nOpen Ports = " + string.Join(",", OpenPorts);
            if (AttacksPeriods != null)    
                info += "\nTime Spans = " + string.Join(",", AttacksPeriods);

            return info;
        }
    }
}

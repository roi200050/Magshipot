using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;

namespace Honeypot
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
            info += "\nOpen Ports = " + string.Join(",", OpenPorts);
            info += "\nTime Spans = " + string.Join(",", AttacksPeriods);

            return info;
        }
    }
}

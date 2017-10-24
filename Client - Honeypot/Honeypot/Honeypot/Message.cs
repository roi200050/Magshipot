using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Honeypot
{
    class Message
    {
        public static List<string> ParseMessage(string msg)
        {
            var elements = new List<string>();
            elements.Add(GetMessageCode(msg));
            return elements.Concat(GetMessageArgs(msg)).ToList<string>();
        }

        private static string GetMessageCode(string msg)
        {
            return msg[1].ToString();
        }

        private static List<string> GetMessageArgs(string msg)
        {
            var raw_args = msg.Substring(3, msg.IndexOf("||") - 3);
            return raw_args.Split(new char[] { '|' }).ToList<string>();
        }

        public static string CollectedInfoToMessage(CollectedInfo inf)
        {
            string info = "@1";
            info += "|" + inf.Date.ToString();
            info += "|" + inf.IP_Address.ToString() + "|";
            if (inf.AttackedPorts != null)
            {
                info += string.Join(",", inf.AttackedPorts);
            }
            info += "|" + inf.Country;
            if (inf.Attacks != null)
            {
                info += "|" + string.Join(",", inf.Attacks);
            }
            info += "|" + inf.NetworkDistance.ToString();
            info += "|" + inf.OS;
            info += "|" + string.Join(",", inf.OpenPorts);
            info += "| " + string.Join(",", inf.AttacksPeriods) + "||";
            return info;
        }
    }
}

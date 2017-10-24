using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Honeypot
{
    class ReturnData
    {
        public string AttackName { get; set; }
        public TimeSpan AttackSpan { get; set; }
        public HashSet<int> PortsAttacked { get; set; }

        public ReturnData(string name, TimeSpan span, HashSet<int> ports)
        {
            AttackName = name;
            AttackSpan = span;
            PortsAttacked = ports;
        }
    }
}

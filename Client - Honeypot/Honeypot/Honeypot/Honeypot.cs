using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Honeypot
{
    class Honeypot
    {
        public Analyzer Analyzer { get; set; }
        public ClientsCommunicator cliCommunicator { get; set; }
        public ServerCommunicator srvCommunicator { get; set; }

        public Honeypot(List<string> SupportedAttacks, int listen_port, int min_ports_scan, string srvr_ip, int srvr_port, string watch_path)
        {
            Analyzer = new Analyzer(SupportedAttacks, min_ports_scan);
            cliCommunicator = new ClientsCommunicator(listen_port);
            srvCommunicator = new ServerCommunicator(System.Net.IPAddress.Parse(srvr_ip), srvr_port);
            var watcher = new FileWatcher(watch_path);
        }
    }
}

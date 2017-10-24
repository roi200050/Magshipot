using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Server___HoneyPot
{
    class Server
    {
        Communicator Comm;
        FirewallManager Firewall_m;

        public Server(int listen_port, int event_listen_port, int process_listen_port)
        {
            Comm = new Communicator(listen_port, event_listen_port, process_listen_port);
        }

        public void Continue(List<int> Honeypots = null)
        {

        }
        public void Pause(List<int> Honeypots = null)
        {

        }
        public void Exit()
        {

        }
    }
}

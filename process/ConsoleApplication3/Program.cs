using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.Diagnostics;

namespace ConsoleApplication3
{
    class Program
    {
        static void Main(string[] args)
        {
            string server_ip = "10.0.0.17";
            int listen_port = 27777;
            var proc = new Process(server_ip ,listen_port);
        }
    }
}

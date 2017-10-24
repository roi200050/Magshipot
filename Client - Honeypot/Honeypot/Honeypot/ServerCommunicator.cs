using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Diagnostics;

namespace Honeypot
{
    class ServerCommunicator
    {
        public const int MAX_HANDLE_THREADS = 3;
        private int HandleThreadsCurrentlyRunning;
        public TcpClient Client { get; set; }
        public static Queue<string> InMessages { get; set; }
        public static Queue<string> OutMessages { get; set; }

        public ServerCommunicator(IPAddress srvr_addr, int srvr_port)
        {
            HandleThreadsCurrentlyRunning = 0;
            try
            {
                Client = new TcpClient(srvr_addr.ToString(), srvr_port);
                var t1 = new Thread(Send);
                var t2 = new Thread(Receive);
                InMessages = new Queue<string>();
                OutMessages = new Queue<string>();
                t1.Start();
                t2.Start();
            }
            catch (Exception)
            {
                Console.WriteLine("Failed to connect to server.");
            }
        }

        public void Send()
        {
            while (true)
            {
                try
                {
                    if (Client.Connected)
                    {
                        if (OutMessages.Count > 0)
                        {
                            Client.Client.Send(Encoding.ASCII.GetBytes(OutMessages.Dequeue()));
                        }
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("Connection is down, exiting program.");
                    Console.WriteLine("Press any key to exit.");
                    Console.ReadKey();
                    Process.GetCurrentProcess().Kill();
                }
            }
        }

        public void Receive()
        {
            string raw_message;
            Byte[] buffer = new Byte[1024];
            while (true)
            {
                try
                {
                    if (Client.Connected)
                    {
                        Client.Client.Receive(buffer);
                        raw_message = Encoding.ASCII.GetString(buffer);
                        raw_message = raw_message.Substring(0, raw_message.IndexOf("||") + 2);
                        InMessages.Enqueue(raw_message);
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("Connection is down, exiting program.");
                    Process.GetCurrentProcess().Kill();
                }
            }
        }

        public void CallHandlers()
        {
            string msg;
            while (true)
            {
                if (InMessages.Count > 0 && HandleThreadsCurrentlyRunning < MAX_HANDLE_THREADS)
                {                    
                    lock (InMessages)
                    {
                        msg = InMessages.Dequeue();
                    }
                    var thread = new Thread(() => HandleMessage(msg));
                    thread.Start();
                }
            }
        }

        public void HandleMessage(string msg)
        {
            HandleThreadsCurrentlyRunning++;
            var parse_res = Message.ParseMessage(msg);
            switch (parse_res[0][0])           // first element in parse_res is the message code
            {
                case '3':
                    var info = ParseInfoMessage(parse_res);
                    break;
                default:
                    break;
            }
            HandleThreadsCurrentlyRunning--;
        }

        public CollectedInfo ParseInfoMessage(List<string> parsed_msg)
        {
            return null;
        }

        public void Disconnect()
        {
            Client.Close();
        }
    }
}

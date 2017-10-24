using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Server___HoneyPot
{
    class Communicator
    {
        private Thread AcceptThread;                      // this thread will accept connection requests from the honeypots
        private Thread SendThread;                        // this thread will send messages from OutMessages
        private Thread ReceiveThread;                     // this thread will receive messages into InMessages
        private Thread HandlersCaller;                    // this thread will create threads that will handle the messages in InMessages
        private Thread EventAcceptThread;                 // this thread will accept connection requests from the FileWatcher event
        private Thread ProcessAcceptThread;                 // this thread will accept connection requests from the process detection event
        private const int MAX_HANDLE_THREADS = 5;
        private int HandleThreadsCurrentlyRunning;
        private SqlManager SQL;
        public TcpListener Listener { get; set; }         // object holding the server socket
        public TcpListener EventListener { get; set; }
        public TcpListener ProcessListener { get; set; }
        public List<TcpClient> Honeypots { get; set; }    // list of all honeypots sockets
        public Queue<Message> InMessages { get; set; }
        public Queue<Message> OutMessages { get; set; }

        private static IPAddress GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return IPAddress.Parse(ip.ToString());
                }
            }
            throw new Exception("Local IP Address Not Found!");
        }

        public Communicator(int listen_port, int event_listen_port, int process_listen_port)
        {
            SQL = new SqlManager();

            InMessages = new Queue<Message>();
            OutMessages = new Queue<Message>();

            IPAddress ip_addr = GetLocalIPAddress();
            Listener = new TcpListener(ip_addr, listen_port);
            EventListener = new TcpListener(ip_addr, event_listen_port);
            ProcessListener = new TcpListener(ip_addr, process_listen_port);
            Honeypots = new List<TcpClient>();
            AcceptThread = new Thread(AcceptConnections);
            EventAcceptThread = new Thread(EventAcceptConnections);
            ProcessAcceptThread = new Thread(ProcessAcceptConnections);
            HandlersCaller = new Thread(CallHandlers);
            SendThread = new Thread(Send);
            ReceiveThread = new Thread(Receive);
            HandleThreadsCurrentlyRunning = 0;

            Console.WriteLine("Listening in: " + ip_addr.ToString() + " : " + listen_port);

            Listener.Start();
            EventListener.Start();
            ProcessListener.Start();
            AcceptThread.Start();
            HandlersCaller.Start();
            SendThread.Start();
            ReceiveThread.Start();
            EventAcceptThread.Start();
            ProcessAcceptThread.Start();
        }

        public void AcceptConnections()
        {
            while (true)
            {
                Honeypots.Add(Listener.AcceptTcpClient());
                Console.WriteLine("Client " + IPAddress.Parse(((IPEndPoint)Honeypots.Last().Client.RemoteEndPoint).Address.ToString()) + " has connected!");
            }
        }

        public void EventAcceptConnections()
        {
            while (true)
            {
                try
                {
                    var client = EventListener.AcceptTcpClient();
                    var buffer = new byte[1024];
                    client.Client.Receive(buffer);
                    Console.WriteLine("Client " + ((IPEndPoint)client.Client.RemoteEndPoint).Address + ": " + Encoding.ASCII.GetString(buffer));
                    var info = Encoding.ASCII.GetString(buffer);
                    info = info.Replace("\0", string.Empty);
                    var lst_info = info.Split('|');
                    SQL.InsertJavaScriptInfo(lst_info[0], lst_info[1], lst_info[2], lst_info[3], lst_info[4], lst_info[5]);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
        }

        public void ProcessAcceptConnections()
        {
            Console.WriteLine("listening on port: " + ((IPEndPoint)(ProcessListener.Server.LocalEndPoint)).Port);
            while (true)
            {
                try
                {
                    var client = ProcessListener.AcceptTcpClient();
                    var buffer = new byte[1024];
                    client.Client.Receive(buffer);
                    Console.WriteLine("Client " + ((IPEndPoint)client.Client.RemoteEndPoint).Address + ": " + Encoding.ASCII.GetString(buffer));
                    var info = Encoding.ASCII.GetString(buffer);
                    info = info.Substring(0, info.LastIndexOf("||") + "||".Length);          //info format: [process name]|[pid]|[port + foregin ip tuples inside < >]||

                    SQL.Insert_ProcessInfo(info);

                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
        }

        public void CallHandlers()
        {
            while (true)
            {
                if (InMessages.Count > 0 && HandleThreadsCurrentlyRunning < MAX_HANDLE_THREADS)
                {
                    Message msg;
                    lock (InMessages)
                    {
                        msg = InMessages.Dequeue();
                    }
                    var thread = new Thread(() => HandleMessage(msg));
                    thread.Start();
                }
            }
        }

        public void HandleMessage(Message msg)
        {
            HandleThreadsCurrentlyRunning++;
            var parse_res = Message.ParseMessage(msg);
            switch (parse_res[0][0])           // first element in parse_res is the message code
            {
                case '1':       // a report on a new connection, need to push all information to the sql tables, no need for a response
                    //SQL.InsertNewHoneypot(IPAddress.Parse(((IPEndPoint)msg.Socket.RemoteEndPoint).Address.ToString()));
                    SQL.Insert_CollectedInfo(new CollectedInfo(parse_res.Skip(1).ToList<string>()));
                    break;
                case '2':       // a request for the collected info about an IP, need to pull all information from the sql tables and push a new message to OutMessages, with the same socket
                    OutMessages.Enqueue(new Message("@3|" + SQL.IsAttacker(Message.ParseMessage(msg)[1]).ToString() + "||", msg.Socket));
                    break;
                default:        // unidentified message code, ignore message
                    break;
            }
            HandleThreadsCurrentlyRunning--;
        }

        public void Send()
        {
            Message to_send;
            while (true)
            {
                if (OutMessages.Count > 0 && Honeypots.Count > 0)
                {
                    lock (OutMessages)
                    {
                        to_send = OutMessages.Dequeue();
                    }
                    Console.WriteLine("Sending message, IP: " + ((IPEndPoint)to_send.Socket.RemoteEndPoint).Address);
                    to_send.Socket.Send(Encoding.ASCII.GetBytes(to_send.Data));
                }
            }
        }

        public void Receive()
        {
            ArrayList read_socket = new ArrayList();
            Byte[] recvbuff;
            string recv_data;
            int recvbuflen = 1024;
            while (true)
            {
                for (int i = 0; i < Honeypots.Count; i++)
                {
                    read_socket.Clear();
                    if (Honeypots[i] != null)
                    {
                        read_socket.Add(Honeypots[i].Client);
                        try
                        {
                            Socket.Select(read_socket, null, null, 500000);
                            if (read_socket.Count > 0)
                            {
                                recvbuff = new Byte[recvbuflen];
                                Honeypots[i].Client.Receive(recvbuff);
                                recv_data = Encoding.ASCII.GetString(recvbuff);
                                if (!string.IsNullOrEmpty(recv_data))
                                {
                                    if (recv_data != "-1")
                                    {
                                        Console.WriteLine("Incoming message, IP: " + ((IPEndPoint)Honeypots[i].Client.RemoteEndPoint).Address);
                                        InMessages.Enqueue(new Message(recv_data, Honeypots[i].Client));
                                        recv_data = "-1";       // "-1" is a special string, used to tell if the buffer was read in the current iteration.
                                    }
                                }
                                else
                                {
                                    Honeypots[i].Client.Close();
                                    Honeypots[i].Close();
                                    Honeypots.RemoveAt(i);    // remove the problematic socket from the clients list
                                    break;                    // break from the current for, so the loop would initiate according to the removal of the socket
                                }
                            }
                        }
                        catch (Exception)
                        {
                            Honeypots[i].Client.Close();
                            Honeypots[i].Close();
                            Honeypots.RemoveAt(i);    // remove the problematic socket from the clients list
                            break;                    // break from the current for, so the loop would initiate according to the removal of the socket
                        }
                    }
                }
            }
        }

        public void Start()
        {

        }

        public void Stop()
        {

        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using PacketDotNet;
using SharpPcap;
using SharpPcap.WinPcap;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;


namespace Honeypot
{
    class ClientsCommunicator
    {
        private Thread SniffThread;          // this thread will constantly sniff network traffic
        private Thread AcceptThread;         // this thread will accept connection requests from clients on port 10000
        private Thread TelnetAcceptThread;   // this thread will accept connection requests from clients on port 23, the TELNET protocol port.
        public TcpListener Listener { get; set; }       // object holding the server socket for port 10000
        public TcpListener TelnetListener { get; set; }       // object holding the server socket for port 23 (telnet)
        public List<TcpClient> Clients { get; set; }    // list of all client sockets on port 10000
        //public List<TcpClient> TelnetClients { get; set; }    // list of all client sockets on port 23 (telnet)


        public ClientsCommunicator(int listen_port)
        {
            IPAddress ip_addr = IPAddress.Any;
            Listener = new TcpListener(ip_addr, listen_port);
            //TelnetListener = new TcpListener(ip_addr, TELNET_PORT);
            //var lingerOption = new LingerOption(true, 10);      // set accept timeout of 10 seconds
            //Listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Linger, lingerOption);
            //Listener.Server.ReceiveTimeout = 10;
            Clients = new List<TcpClient>();
            //TelnetClients = new List<TcpClient>();
            AcceptThread = new Thread(AcceptConnections);
            //TelnetAcceptThread = new Thread(AcceptTelnetConnection);
            SniffThread = new Thread(SniffConnection);
            Listener.Start();
            //TelnetListener.Start();
            SniffThread.Start();
            AcceptThread.Start();
            //TelnetAcceptThread.Start();
        }

        //public void AcceptTelnetConnection()
        //{
        //    while (true)
        //    {
        //        TcpClient client = null;
        //        client = TelnetListener.AcceptTcpClient();
        //        try
        //        {
        //            client.Client.Send(ASCIIEncoding.ASCII.GetBytes("Welcome to my Telnet!\n"));              // let the attacker think there's a telnet service open on port 23.
        //        }
        //        catch (Exception)
        //        {
        //            continue;
        //        }
        //        TelnetClients.Add(client);
        //        Console.WriteLine("Telnet Client " + ((IPEndPoint)TelnetClients.Last().Client.RemoteEndPoint).Address.ToString() + " has connected!");
        //    }
        //}

        public void AcceptConnections()
        {
            while (true)
            {
                TcpClient client = null;
                client = Listener.AcceptTcpClient();
                try
                {
                    client.Client.Send(ASCIIEncoding.ASCII.GetBytes("Please enter your password: "));       // give the attacker the impression theres a db that can be attacked with sql injection
                }
                catch (Exception)
                {
                    continue;
                }
                Clients.Add(client);
                Console.WriteLine("Client " + ((IPEndPoint)Clients.Last().Client.RemoteEndPoint).Address.ToString() + " has connected!");
            }
        }

        public void SniffConnection()
        {
            //var packets = new List<RawCapture>();
            LibPcapLiveDevice device = null;
            CaptureFileWriterDevice FileWriter = null;
            var devices = CaptureDeviceList.Instance;
            foreach (var dev in devices)
            {
                if (((LibPcapLiveDevice)dev).Interface.FriendlyName.Equals("Wi-Fi 3"))      // check for the interface to capture from          "Wireless Network Connection"))//
                {
                    device = (LibPcapLiveDevice)dev;
                    break;
                }
            }

            try
            {
                //Open the device for capturing
                device.Open(DeviceMode.Promiscuous);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return;
            }

            //Register our handler function to the 'packet arrival' event
            //device.OnPacketArrival += (sender, packets_storage) => PacketArrivalHandler(sender, ref packets);

            //set filter for device
            //device.Filter = "(ip src " + ((IPEndPoint)client.Client.LocalEndPoint).Address + " and ip dst " + ((IPEndPoint)client.Client.RemoteEndPoint).Address
            //    + ") or (ip src " + ((IPEndPoint)client.Client.RemoteEndPoint).Address + " and ip dst " + ((IPEndPoint)client.Client.LocalEndPoint).Address + ")";

            Console.WriteLine("sniffing...");
            int packets_count;
            try
            {
                //device.Capture();
                RawCapture raw;
                while (true)
                {
                    FileWriter = new CaptureFileWriterDevice(DateTime.Now.ToString("yyyy-dd-M--HH-mm-ss") + ".pcap", System.IO.FileMode.Create);
                    packets_count = 0;
                    while (packets_count < 20)
                    {
                        raw = device.GetNextPacket();

                        if (raw != null)
                        {
                            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
                            var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));
                            var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));
                            if (ipPacket != null && tcpPacket != null)
                            {
                                if (!ipPacket.SourceAddress.Equals(Analyzer.GetCurrentIPAddress()))       // if packet wasn't sent by the honeypot itself
                                {
                                    FileWriter.Write(raw);
                                    packets_count++;
                                    Console.WriteLine(packets_count);
                                }
                            }
                        }
                    }

                    if (FileWriter != null)
                    {
                        lock (Analyzer.AnalyzeQueue)
                        {
                            Analyzer.AnalyzeQueue.Enqueue(FileWriter.Name);
                        }
                        FileWriter.Close();
                    }
                }
            }
            catch (System.AccessViolationException e)
            {
                Console.WriteLine(e);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            Console.WriteLine("finished sniffing");
            //Console.ReadLine();
            //System.Diagnostics.Process.GetCurrentProcess().Kill();
        }

        //public static void PacketArrivalHandler(object sender, ref List<RawCapture> packets)
        //{
        //    var dev = (WinPcapDevice)sender;
        //    RawCapture p = dev.GetNextPacket();
        //    if (p != null)
        //    {
        //        var raw_packet = Packet.ParsePacket(p.LinkLayerType, p.Data);       // split the packet into layers to check the data in layers is valid
        //        var tcpPacket = (TcpPacket)raw_packet.Extract(typeof(TcpPacket));
        //        var ipPacket = (IpPacket)raw_packet.Extract(typeof(IpPacket));
        //        packets.Add(p);
        //    }
        //}
    }
}

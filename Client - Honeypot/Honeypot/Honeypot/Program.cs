using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using PacketDotNet;
using SharpPcap;
using SharpPcap.WinPcap;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;
using System.IO;


namespace Honeypot
{
    class Program
    {
        static void Main(string[] args)
        {
            const string SERVER_IP = "10.0.0.17";
            //var temp = new ClientsCommunicator(10000);
            
            var lst = new List<string>();
            lst.Add("PortScan");
            //lst.Add("DOS");
            lst.Add("SQLInjection");
            lst.Add("XSS");
            var temp = new Honeypot(lst, 10000, 10, SERVER_IP, 27016, "C:\\MAMP\\htdocs\\logs");

            //TcpClient c = new TcpClient("192.168.1.38", 27016);
            //var hs = new HashSet<int>();
            //hs.Add(10000);
            //var l = new List<string>();
            //l.Add("attack");
            //var s = new List<int>();
            //s.Add(5);
            //var t = new List<TimeSpan>();
            //t.Add(new TimeSpan(1, 1, 1));
            //CollectedInfo ci = new CollectedInfo(DateTime.Now, IPAddress.Parse("127.0.0.1"), hs, "israel", l, 2, "windows", s, t);
            //c.Client.Send(Encoding.ASCII.GetBytes(Message.CollectedInfoToMessage(ci)));
            //Console.WriteLine("sent");

            //Console.Write("Hit 'Enter' to exit...");
            //Console.ReadLine();
        }





        //public static List<RawCapture> SniffConnection()
        //{
        //    var packets = new List<RawCapture>();
        //    var devices = CaptureDeviceList.Instance;
        //    PcapDevice device = null;

        //    foreach (var dev in devices)
        //    {
        //        if (((LibPcapLiveDevice)dev).Interface.FriendlyName.Equals("Wi-Fi 3"))
        //        {
        //            device = (LibPcapLiveDevice)dev;
        //            break;
        //        }
        //    }

        //    try
        //    {
        //        //Open the device for capturing
        //        device.Open(DeviceMode.Promiscuous);
        //    }
        //    catch (Exception e)
        //    {
        //        Console.WriteLine(e.Message);
        //        return null;
        //    }

        //    //Register our handler function to the 'packet arrival' event
        //    //device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(PacketArrivalHandler);
        //    device.OnPacketArrival += (sender, packets_storage) => PacketArrivalHandler(sender, ref packets);

        //    //This method will return when EOF reached.
        //    Console.WriteLine("sniffing...");
        //    device.Capture(10);
        //    device.Close();
        //    return packets;
        //}

        //public static void PacketArrivalHandler(object sender, ref List<RawCapture> packets)
        //{
        //    var dev = (WinPcapDevice)sender;
        //    RawCapture i = dev.GetNextPacket();
        //    if (i != null)
        //    {
        //        var raw_packet = Packet.ParsePacket(i.LinkLayerType, i.Data);
        //        var tcpPacket = (TcpPacket)raw_packet.Extract(typeof(TcpPacket));
        //        var ipPacket = (IpPacket)raw_packet.Extract(typeof(IpPacket));
        //        packets.Add(i);
        //    }
        //}
    }
}











            //PortScan ps = new PortScan("PortScan", 1);
            //Console.WriteLine(ps.Check("D:\\Users\\user-pc\\Documents\\Magshimim\\Honeypot\\Honeypot\\file.pcap") ? "YES" : "NO");
            //Console.WriteLine(NmapAdapter.AnalyzeIP(IPAddress.Parse("193.46.64.211")));
//            NmapAdapter.GetLocation(@"
//Starting Nmap 6.40 ( http://nmap.org ) at 2016-01-30 14:26 Jerusalem Standard Time
//Nmap scan report for www.israelpost.co.il (193.46.64.211)
//Host is up (0.035s latency).
//Not shown: 998 filtered ports
//PORT    STATE SERVICE
//80/tcp  open  http
//443/tcp open  https
//
//Host script results:
//| ip-geolocation-geoplugin: 
//| 193.46.64.211
//|   coordinates (lat,lon): 31.5,34.75
//|_  state: Unknown, Israel
//|_ip-geolocation-maxmind: ERROR: Script execution failed (use -d to debug)
//
//Nmap done: 1 IP address (1 host up) scanned in 20.91 seconds
//");
            //SQLInjection si = new SQLInjection("SQLInjection");
            //Console.WriteLine(si.Check("packets.pcap") ? "YES" : "NO");
            //PortScan ps = new PortScan("PortScan", 1);
            //Console.WriteLine(ps.Check("file.pcap") ? "YES" : "NO");
        //}


        //string capFile = "D:\\Users\\user-pc\\Documents\\Magshimim\\Honeypot\\Honeypot\\file.pcap";
        //    PcapDevice device;
        //    try
        //    {
        //        //Get an offline file pcap device
        //        //device = GetPcapOfflineDevice(capFile);
        //        device = new CaptureFileReaderDevice(capFile);
        //        //Open the device for capturing
        //        device.Open();
        //    }
        //    catch (Exception e)
        //    {
        //        Console.WriteLine(e.Message);
        //        return;
        //    }
        //    //Register our handler function to the 'packet arrival' event
        //    device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(PacketArrivalHandler);
        //    Console.WriteLine();
        //    Console.WriteLine("-- Capturing from '{0}', hit 'Ctrl-C' to exit...", capFile);
        //    //Start capture 'INFINTE' number of packets
        //    //This method will return when EOF reached.
        //    device.Capture();
        //    //Close the pcap device
        //    device.Close();
        //    Console.WriteLine("-- End of file reached.");


        //private static void PacketArrivalHandler(object sender, CaptureEventArgs e)
        //{
        //    CaptureFileReaderDevice dev = (CaptureFileReaderDevice)sender;
        //    RawCapture raw = dev.GetNextPacket();
        //    //var f = File.AppendText("D:\\Users\\user-pc\\Desktop\\packets.txt");
        //    //f.WriteLine(Encoding.ASCII.GetString(raw.Data) + "\n\n\n\n\n");
        //    var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
        //    var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));
        //    var p = (IpPacket)packet.Extract(typeof(IpPacket));
        //    if (tcpPacket != null)
        //    {
        //        Console.WriteLine(tcpPacket.DestinationPort + "\t\t" + p.DestinationAddress);
        //    }
        //}

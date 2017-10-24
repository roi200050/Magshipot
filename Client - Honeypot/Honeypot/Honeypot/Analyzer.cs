using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using PacketDotNet;
using SharpPcap;
using SharpPcap.WinPcap;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;


namespace Honeypot
{
    class Analyzer
    {
        public static Queue<string> AnalyzeQueue { get; set; }
        public List<Attack> allSupportedAttacks { get; set; }
        public Thread AnalyzeThread { get; set; }

        //const int MAX_ANALYZE_THREADS = 5;
        //public Thread CallAnalyzingThread { get; set; }
        //private int AnalyzeThreadsCurrentlyRunning;

        public Analyzer(List<string> attack_names, int min_ports_count_for_port_scan)
        {
            allSupportedAttacks = new List<Attack>();
            AnalyzeQueue = new Queue<string>();
            //AnalyzeThreadsCurrentlyRunning = 0;
            foreach (string a in attack_names)
            {
                Attack att = null;
                switch (a)
                {
                    // add another case in order to add an attack
                    case "SQLInjection":
                        att = new SQLInjection(a);
                        break;
                    case "PortScan":
                        att = new PortScan(a, min_ports_count_for_port_scan);
                        break;
                    case "XSS":
                        att = new XSS(a);
                        break;
                    //case "DOS":
                    //    att = new DOS("DOS", min_syns_count_for_syn_flood);
                    //    break;
                    //case "TelnetConnection":
                    //    att = new TelnetConnection(a);
                    //    break;
                    //case "LAND":
                    //    att = new LAND(a);
                    //    break;
                }

                if (att != null)
                {
                    allSupportedAttacks.Add(att);
                }
            }

            AnalyzeThread = new Thread(AnalyzeSniffFile);
            AnalyzeThread.Start();
            //CallAnalyzingThread = new Thread(CallAnalyzers);
            //CallAnalyzingThread.Start();
        }

        public static List<RawCapture> ReadPackets(string capFilePath)
        {
            var Packets = new List<RawCapture>();
            Packets.Clear();
            PcapDevice device;
            try
            {
                //Get an offline file pcap device
                device = new CaptureFileReaderDevice(capFilePath);
                //Open the device for capturing
                device.Open();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }

            //Register our handler function to the 'packet arrival' event
            //device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(PacketArrivalHandler);

            //This method will return when EOF reached.
            //device.Capture();

            RawCapture currPacket;
            do
            {
                currPacket = device.GetNextPacket();
                if (currPacket != null)
                {
                    Packets.Add(currPacket);
                }
            } while (currPacket != null);

            device.Close();
            return Packets;
        }

        public void AnalyzeSniffFile()
        {
            string filename;
            while (true)
            {
                if (AnalyzeQueue.Count > 0)
                {
                    lock (AnalyzeQueue)
                    {
                        filename = AnalyzeQueue.Dequeue();
                    }
                    var check_res = CheckAttacks(filename);
                    var att_ip = GetAttackerIP(filename);
                    CollectedInfo colInfo;
                    if (!att_ip.Equals(GetCurrentIPAddress()))
                    {
                        colInfo = NmapAdapter.AnalyzeHost(att_ip);
                    }
                    else
                    {
                        colInfo = new CollectedInfo(DateTime.Now, IPAddress.Any, null, "NONE", null, 0, "NONE", new List<int>(), null);
                    }
                    colInfo.Attacks = check_res.Item1;
                    colInfo.AttacksPeriods = check_res.Item2;
                    colInfo.AttackedPorts = check_res.Item3;

                    var msg_col_info = Message.CollectedInfoToMessage(colInfo);
                    if (ServerCommunicator.OutMessages != null)
                    {
                        lock (ServerCommunicator.OutMessages)
                        {
                            ServerCommunicator.OutMessages.Enqueue(msg_col_info);
                        }
                    }
                }
            }
        }


        // input parameter of function - pcap file path
        public Tuple<List<string>, List<TimeSpan>, HashSet<int>> CheckAttacks(string filename)
        {
            var attacks = new List<string>();
            var times = new List<TimeSpan>();
            var ports = new List<HashSet<int>>();
            ReturnData ret_data;
            foreach (var att in allSupportedAttacks)
            {
                if ((ret_data = att.Check(filename)) != null)
                {
                    attacks.Add(att.Name);
                    times.Add(ret_data.AttackSpan);
                    ports.Add(ret_data.PortsAttacked);
                }
            }

            var fin_ports = new HashSet<int>();
            foreach (var curr_ports in ports)
            {
                foreach (var port in curr_ports)
                {
                    fin_ports.Add(port);
                }
            }


            return new Tuple<List<string>, List<TimeSpan>, HashSet<int>>(attacks, times, fin_ports);
        }

        public static IPAddress GetCurrentIPAddress()
        {
            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (IPAddress ip in host.AddressList)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    return ip;
                }
            }
            return null;
        }

        public IPAddress GetAttackerIP(string filename)
        {
            var packets = ReadPackets(filename);
            var my_ip = GetCurrentIPAddress();
            foreach (var packet in packets)
            {
                var raw_packet = Packet.ParsePacket(packet.LinkLayerType, packet.Data);
                var ipPacket = (IpPacket)raw_packet.Extract(typeof(IpPacket));

                if (!ipPacket.SourceAddress.Equals(my_ip))
                {
                    return ipPacket.SourceAddress;
                }
            }

            return null;
        }
    }
}



//public void CallAnalyzers() {
//    while (true)
//    {
//        if (AnalyzeQueue.Count > 0 && AnalyzeThreadsCurrentlyRunning < MAX_ANALYZE_THREADS)     // if there are connections to analyze and there are less analyze threads currently working than the allowed max
//        {
//            string filename;
//            lock (AnalyzeQueue)
//            {
//                filename = AnalyzeQueue.Dequeue();
//            }

//            // create new thread to analyze connection
//            var thread = new Thread(() => AnaylzeConnection(filename));
//            thread.Start();
//        }
//    }
//}

//public void AnaylzeConnection(string filename)
//{
//    AnalyzeThreadsCurrentlyRunning++;
//    //var attacks = CheckAttacks(filename);
//    //var colInfo = NmapAdapter.AnalyzeHost(IPAddress.Parse(filename.Substring(0, filename.Length - ".pcap".Length)), 10000);
//    //colInfo.Attacks = attacks;
//    // TO DO: add colInfo to the send-queue of the server communicator
//    AnalyzeThreadsCurrentlyRunning--;
//}



using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using SharpPcap.WinPcap;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;


namespace Honeypot
{
    class DOS : Attack
    {
        private int min_syns;

        public DOS(string att_name, int min) : base()
        {
            Name = att_name;
            min_syns = min;
        }

        public override ReturnData Check(string capFilePath)
        {
            //return IsDOS(Analyzer.ReadPackets(capFilePath));
            return null;
        }

        /* iterates over all packets in pcap file, counts how many SYN packets were sent to a specific port on the honeypot. 
           More than min_syns can be considered a DOS attack. */
        private bool IsDOS(List<RawCapture> Packets)
        {
            var ports_requests = new Hashtable();
            foreach (var packet in Packets)
            {
                var raw_packet = Packet.ParsePacket(packet.LinkLayerType, packet.Data);
                var tcpPacket = (TcpPacket)raw_packet.Extract(typeof(TcpPacket));
                var ipPacket = (IpPacket)raw_packet.Extract(typeof(IpPacket));

                if (tcpPacket != null && ipPacket != null)
                {
                    if (ipPacket.DestinationAddress == Analyzer.GetCurrentIPAddress() && tcpPacket.Syn)
                    {
                        if (ports_requests.ContainsKey(tcpPacket.DestinationPort))
                        {
                            if ((int)ports_requests[tcpPacket.DestinationPort] > min_syns)
                            {
                                return true;
                            }
                            else
                            {
                                int temp = (int)ports_requests[tcpPacket.DestinationPort];
                                temp++;
                                ports_requests[tcpPacket.DestinationPort] = temp;
                            }
                        }
                        else
                        {
                            ports_requests[tcpPacket.DestinationPort] = 1;
                        }
                    }
                }
            }

            return false;
        }
    }
}

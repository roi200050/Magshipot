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
//using HexHelper = SharpPcap.Packets.Util.HexHelper;
//using Timeval = SharpPcap.Packets.Util.Timeval;
//using Timeval = SharpPcap.PosixTimeval;

namespace Honeypot
{
    class PortScan : Attack
    {
        private int min_ports;

        public PortScan(string att_name, int min)
            : base()
        {
            Name = att_name;
            min_ports = min;
        }

        public override ReturnData Check(string capFilePath)
        {
            return IsPortScan(Analyzer.ReadPackets(capFilePath));
        }


        private ReturnData IsPortScan(List<RawCapture> Packets)
        {
            var att_start = Packets[0].Timeval.Date;
            var att_end = Packets.Last().Timeval.Date;
            var ports_entries = new HashSet<int>();
            var my_ip = Analyzer.GetCurrentIPAddress();
            foreach (var packet in Packets)
            {
                var raw_packet = Packet.ParsePacket(packet.LinkLayerType, packet.Data);
                //var e = new CaptureEventArgs(packet, null);
                var tcpPacket = (TcpPacket)raw_packet.Extract(typeof(TcpPacket));
                var ipPacket = (IpPacket)raw_packet.Extract(typeof(IpPacket));

                if (tcpPacket != null && ipPacket != null)
                {
                    if (ipPacket.DestinationAddress.Equals(my_ip) && tcpPacket.Syn && !tcpPacket.Ack)
                    {
                        ports_entries.Add(tcpPacket.DestinationPort);

                    }
                }
            }

            if (ports_entries.Count > min_ports)
            {
                return new ReturnData(this.Name, att_end - att_start, ports_entries);
            }
            return null;
        }
    }
}

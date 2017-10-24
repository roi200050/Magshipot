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
    class SQLInjection : Attack
    {
        public SQLInjection(string att_name) : base()
        {
            Name = att_name;
        }

        public override ReturnData Check(string capFilePath)
        {
            return IsSQLInjection(Analyzer.ReadPackets(capFilePath));
        }

        private ReturnData IsSQLInjection(List<RawCapture> Packets)
        {
            var att_start = Packets[0].Timeval.Date;
            foreach (var packet in Packets)
            {
                var raw_packet = Packet.ParsePacket(packet.LinkLayerType, packet.Data);
                var tcpPacket = (TcpPacket)raw_packet.Extract(typeof(TcpPacket));
                var ipPacket = (IpPacket)raw_packet.Extract(typeof(IpPacket));
                
                if (tcpPacket != null && ipPacket != null)
                {
                    string raw_data = System.Text.Encoding.Default.GetString(raw_packet.PayloadPacket.PayloadPacket.PayloadData);
                    if (IsSQLInjectionTemplate(raw_data))
                    {
                        return new ReturnData(this.Name, Packets.Last().Timeval.Date - att_start, new HashSet<int>() { tcpPacket.DestinationPort });
                    }
                }
            }

            return null;
        }

        private bool IsSQLInjectionTemplate(string Template)
        {
            // every string with the char ' is not allowed
            if (Template.IndexOf('\'') != -1)     // if ' in the string (for example: ' OR 'a'='a) 
            {
                return true;
            }
            return false;
        }
    }
}

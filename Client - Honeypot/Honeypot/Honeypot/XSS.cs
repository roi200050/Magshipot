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
using System.IO;
using System.Text.RegularExpressions;
//using HexHelper = SharpPcap.Packets.Util.HexHelper;
//using Timeval = SharpPcap.Packets.Util.Timeval;
//using Timeval = SharpPcap.PosixTimeval;

namespace Honeypot
{
    class XSS : Attack
    {
        public XSS(string att_name)
            : base()
        {
            Name = att_name;
        }

        public override ReturnData Check(string capFilePath)
        {
            return IsXSS(Analyzer.ReadPackets(capFilePath));
        }

        public ReturnData IsXSS(List<RawCapture> Packets)
        {
            var my_ip = Analyzer.GetCurrentIPAddress();
            foreach (var packet in Packets)
            {
                var raw_packet = Packet.ParsePacket(packet.LinkLayerType, packet.Data);
                //var e = new CaptureEventArgs(packet, null);
                var tcpPacket = (TcpPacket)raw_packet.Extract(typeof(TcpPacket));
                var ipPacket = (IpPacket)raw_packet.Extract(typeof(IpPacket));

                if (tcpPacket != null && ipPacket != null)
                {
                    if (ipPacket.DestinationAddress.Equals(my_ip))
                    {
                        var payload_data = tcpPacket.PayloadData;
                        if (payload_data != null)
                        {
                            if (payload_data.Length > 0)
                            {
                                var payload_str = Encoding.ASCII.GetString(payload_data);
                                if (ScriptXSS(payload_str))
                                {
                                    return new ReturnData("Script Tag XSS", TimeSpan.Zero, new HashSet<int> { tcpPacket.DestinationPort });
                                }
                                if (ImgXSS(payload_str))
                                {
                                    return new ReturnData("Img Tag XSS", TimeSpan.Zero, new HashSet<int> { tcpPacket.DestinationPort });
                                }
                            }
                        }
                    }
                }
            }

            return null;
        }


        public bool ScriptXSS(string buffer)
        {
            string pattern = "((\x3C)|<)((\x2F)|\\/)*[a-z0-9]+((\x3E)|>)";        /*((\%3C)|<) - check for opening angle bracket or hex equivalent
                                                                                    ((\%2F)|\/)* - the forward slash for a closing tag or its hex equivalent
                                                                                    [a-z0-9\%]+ - check for alphanumeric string inside the tag, or hex representation of these
                                                                                    ((\%3E)|>) - check for closing angle bracket or hex equivalent */
            var rgx = new Regex(pattern);
            var matches = rgx.Matches(buffer);
            return matches.Count > 0;
        }

        public bool ImgXSS(string buffer)
        {
            string pattern = "((\x3C)|<)((\x69)|i|(\x49))((\x6D)|m|(\x4D))((\x67)|g|(\x47))[^\n]+((\x3E)|>)";     /*(\%3C)|<) opening angled bracket or hex equivalent
                                                                                                                    (\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47) the letters 'img' in varying combinations of ASCII, 
                                                                                                                    or upper or lower case hex equivalents 
                                                                                                                    [^\n]+ any character other than a new line following the <img
                                                                                                                    (\%3E)|>) closing angled bracket or hex equivalent */
            var rgx = new Regex(pattern);
            var matches = rgx.Matches(buffer);
            return matches.Count > 0;
        }
    }
}

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


namespace Honeypot
{
    abstract class Attack
    {
        public string Name { get; set; }

        public Attack()
        {
            //Packets = new List<RawCapture>();
        }

        public abstract ReturnData Check(string capFilePath);


        //private void PacketArrivalHandler(object sender, CaptureEventArgs e)
        //{
        //    CaptureFileReaderDevice dev = (CaptureFileReaderDevice)sender;
        //    Packets.Add(dev.GetNextPacket());
        //}
    }
}

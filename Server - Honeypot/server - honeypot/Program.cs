using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;

namespace Server___HoneyPot
{
    class Program
    {
        static void Main(string[] args)
        {
            var srvr = new Server(27016, 22222, 27777);

            //SqlManager SQL = new SqlManager();
            ////SQL.Insert_ProcessInfo("spy|1234|<9209.1.2.3.4><4444.1.2.3.4>||");
            //var PariodTime = new List<TimeSpan>();
            //PariodTime.Add(new TimeSpan(0, 0, 21));
            ////PariodTime.Add(new TimeSpan(0, 0, 22));
            ////PariodTime.Add(new TimeSpan(0, 0, 32));
            //var AttackedPorts = new HashSet<int>();
            //AttackedPorts.Add(123);
            ////AttackedPorts.Add(124);
            //SQL.Insert_CollectedInfo(new CollectedInfo(
            //    new DateTime(2016, 6, 2),
            //    IPAddress.Parse("192.168.43.73"),
            //    AttackedPorts,
            //    "IL",
            //    "PortScan".Split(',').ToList(),
            //    1,
            //    "linux",
            //    "1,2,3,4".Split(',').Select(Int32.Parse).ToList(),
            //    PariodTime));
            //SQL.InsertJavaScriptInfo("192.168.14.12", "Linux", "IE", "4.5", "He", "True");
            //Console.WriteLine(SQL.IsAttacker("192.168.14.17"));
            
            //Communicator com = new Communicator(8002);
        }
    }
}

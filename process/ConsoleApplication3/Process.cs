using System;
using System.Collections.Generic;
using System.Collections;
using System.Linq;
using System.Linq.Expressions;
using System.Management;
using System.Text;
using System.Net.Sockets;

class Process
{
    public static string SERVER_IP { get; set; }
    public static int PORT { get; set; }

    public Process(string server_ip, int listen_port)
    {
        SERVER_IP = server_ip;
        PORT = listen_port;
        ManagementEventWatcher startWatch = new ManagementEventWatcher(
          new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
        startWatch.EventArrived += new EventArrivedEventHandler(startWatch_EventArrived);
        startWatch.Start();
        ManagementEventWatcher stopWatch = new ManagementEventWatcher(
          new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
        stopWatch.EventArrived += new EventArrivedEventHandler(stopWatch_EventArrived);
        stopWatch.Start();
        Console.WriteLine("Press any key to exit");
        while (!Console.KeyAvailable) System.Threading.Thread.Sleep(50);
        startWatch.Stop();
        stopWatch.Stop();
    }

    public static Hashtable PidPortsMapping()
    {
        /* Execute netstat command, save output */
        System.Diagnostics.Process p = new System.Diagnostics.Process();
        p.StartInfo.FileName = "netstat";
        p.StartInfo.Arguments = "-aon";
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
        string netstat_out = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        p.StandardOutput.DiscardBufferedData();

        Hashtable pids = new Hashtable();

        var lines = netstat_out.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries).ToList();
        lines = lines.Skip(2).ToList<string>();

        foreach (var line in lines)
        {
            if (line.Contains("["))
            {
                continue;
            }
            var pid = int.Parse(line.Substring(71));
            var colon = line.IndexOf(':');
            var port = int.Parse(line.Substring(colon + 1, line.IndexOf(' ', colon) - colon - 1));
            var foreign_ip = line.Substring(32, line.LastIndexOf(':') - 32);

            if (!pids.ContainsKey(pid))     // if hashtable doesn't contain the current pid, initialize list of ports open from that pid
            {
                pids[pid] = new HashSet<Tuple<int, string>>();
            }
            var lst = (HashSet<Tuple<int, string>>)(pids[pid]);     // insert to hashtable
            lst.Add(new Tuple<int, string>(port, foreign_ip));
        }
        return pids;
    }

    public static HashSet<Tuple<int, string>> GetPortsByPid(int pid)
    {
        var map = PidPortsMapping();
        var ports = (HashSet<Tuple<int, string>>)map[pid];
        return ports;
    }

    static void stopWatch_EventArrived(object sender, EventArrivedEventArgs e)
    {
        //Console.WriteLine("Process stopped: {0}", e.NewEvent.Properties["ProcessName"].Value);
    }

    static void startWatch_EventArrived(object sender, EventArrivedEventArgs e)
    {
        Byte[] msg;
        Console.WriteLine("Process started: {0}", e.NewEvent.Properties["ProcessName"].Value);
        var process_name = (string)e.NewEvent.Properties["ProcessName"].Value;
        if (!process_name.Equals("NETSTAT.EXE"))
        {
            var temp = System.Diagnostics.Process.GetProcessesByName(process_name.Substring(0, process_name.Length - 4));
            if (temp.Length > 0)
            {
                var new_temp = (from p in temp
                                orderby p.StartTime ascending
                                select p).ToList();
                System.Diagnostics.Process process = new_temp.Last();
                var ports_ip_hs = GetPortsByPid(process.Id);
                //if (ports_ip_hs != null)
                {
                    //if (ports_ip_hs.Count > 0)
                    {
                        string owner = GetProcessOwner(process.Id);
                        if (!owner.Equals("NO OWNER") && !owner.Equals("SYSTEM"))
                        {
                            try
                            {
                                var client = new TcpClient(SERVER_IP, PORT);
                                //if (client.Connected)
                                {
                                    msg = Encoding.ASCII.GetBytes(process.ProcessName + "|" + process.Id + "|" + PortsIPHashsetToString(ports_ip_hs) + "||");
                                    client.Client.Send(msg);
                                    Console.WriteLine("Report on process " + process.ProcessName + " was sent.");
                                    client.Close();
                                }
                            }
                            catch (Exception)
                            {
                                Console.WriteLine("Report on process " + process.ProcessName + " has failed.");
                            }
                        }
                    }
                }
            }
        }
    }

    static string GetProcessOwner(int processId)
    {
        string query = "Select * From Win32_Process Where ProcessID = " + processId;
        ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
        ManagementObjectCollection processList = searcher.Get();

        foreach (ManagementObject obj in processList)
        {
            string[] argList = new string[] { string.Empty, string.Empty };
            try
            {
                int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
                if (returnVal == 0)
                {
                    // return DOMAIN\user
                    //return argList[1] + "\\" + argList[0];

                    return argList[0];		//return just the user
                }
            }
            catch (Exception)
            {

                Console.WriteLine("failed");
            }
        }
        return "NO OWNER";
    }

    static string PortsIPHashsetToString(HashSet<Tuple<int, string>> hs)
    {
        var str = "";
        foreach (var tup in hs)
        {
            str = str + "<" + tup.Item1 + "," + tup.Item2 + ">";
        }
        return str;
    }
}
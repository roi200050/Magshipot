using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;


namespace Honeypot
{
    static class NmapAdapter
    {
        public static CollectedInfo AnalyzeHost(IPAddress ip)
        {
            var time = DateTime.Now;

            System.Diagnostics.Process p = new System.Diagnostics.Process();

            // get os + services + network distance analysis
            p.StartInfo.FileName = "nmap.exe";
            p.StartInfo.Arguments = " -sS -O " + ip.ToString();
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.UseShellExecute = false;
            p.Start();
            string analysis_os_services_distance = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            p.StandardOutput.DiscardBufferedData();

            // get country + coordinations analysis
            p.StartInfo.Arguments = "-Pn -script ip-geolocation-* " + ip.ToString();
            p.Start();
            string location_analysis = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            p.StandardOutput.DiscardBufferedData();

            return new CollectedInfo(time, ip, null, GetLocation(location_analysis), null, GetNetworkDistance(analysis_os_services_distance), GetOS(analysis_os_services_distance), GetOpenPorts(analysis_os_services_distance), null);
        }


        /* returns a list of all open services on the host */
        private static List<int> GetOpenPorts(string nmap_res)
        {
            var services = new List<int>();
            int ports_start = nmap_res.IndexOf("SERVICE") + "SERVICE".Length + 2;
            int ports_end = nmap_res.IndexOf("MAC");
            int slash;
            int port_start = ports_start;
            while (port_start < ports_end)
            {
                slash = nmap_res.IndexOf('/', port_start);
                string s = nmap_res.Substring(port_start, slash - port_start);

                int output;
                if (int.TryParse(s, out output))
                {
                    services.Add(output);
                }
                else
                {
                    Console.WriteLine(s);
                    break;

                }
                port_start = nmap_res.IndexOf('\n', slash) + 1;
            }
            return services;
        }

        /* returns the operating system running on the host */
        private static string GetOS(string nmap_res)
        {
            var idx = nmap_res.IndexOf("Running:");
            if (idx == -1)
            {
                return "NONE";
            }
            int os_start = idx + "Running:".Length + 1;
            int os_end = nmap_res.IndexOf('\r', os_start);
            return nmap_res.Substring(os_start, os_end - os_start);
        }

        private static int GetNetworkDistance(string nmap_res)
        {
            var idx = nmap_res.IndexOf("Network Distance:");
            if (idx == -1)
            {
                return -1;
            }
            int distance_start = idx + "Network Distance:".Length + 1;
            int distance_end = nmap_res.IndexOf(" hop", distance_start);
            var temp = nmap_res.Substring(distance_start, distance_end - distance_start);
            return int.Parse(temp);
        }

        private static string GetLocation(string nmap_res)
        {
            var idx = nmap_res.IndexOf("(lat,lon): ");
            if (idx == -1)
            {
                return "NONE";
            }
            int coordinates_start = idx + "(lat,lon): ".Length;
            int coordinates_end = nmap_res.IndexOf('\r', coordinates_start);
            string coordinates = nmap_res.Substring(coordinates_start, coordinates_end - coordinates_start);

            int country_start = nmap_res.IndexOf("state: ") + "state: ".Length;
            int country_end = nmap_res.IndexOf('\r', country_start);
            if (nmap_res.IndexOf("Unknown", country_start) != -1)
            {
                country_start += "Unknown, ".Length;
            }

            return coordinates + "(" + nmap_res.Substring(country_start, country_end - country_start) + ")";
        }
    }
}

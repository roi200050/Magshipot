using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Server___HoneyPot
{
    class Message
    {
        public string Data { get; set; }
        public Socket Socket { get; set; }

        public Message(string d, Socket s)
        {
            Data = d;
            Socket = s;
        }

        public static List<string> ParseMessage(Message msg) 
        {
            var elements = new List<string>();
            elements.Add(GetMessageCode(msg));
            return elements.Concat(GetMessageArgs(msg)).ToList<string>();
        }

        private static string GetMessageCode(Message msg)
        {
            return msg.Data.Substring(1, 1);
        }

        private static List<string> GetMessageArgs(Message msg)
        {
            var raw_args = msg.Data.Substring(3, msg.Data.LastIndexOf("||") - 3);
            return raw_args.Split( new char[] { '|' } ).ToList<string>();
        }
    }
}

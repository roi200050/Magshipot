using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net.Sockets;

namespace Honeypot
{
    class FileWatcher
    {
        FileSystemWatcher watcher;

        public FileWatcher(string path)
        {
            watcher = new FileSystemWatcher();
            watcher.Path = path;

            /* Watch for changes in LastAccess and LastWrite times, and
               the renaming of files or directories. */
            watcher.NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite
               | NotifyFilters.FileName | NotifyFilters.DirectoryName;

            // Only watch text files.
            watcher.Filter = "*.txt";

            // Add event handlers.
            watcher.Changed += new FileSystemEventHandler(OnChanged);
            watcher.Created += new FileSystemEventHandler(OnChanged);
            watcher.Deleted += new FileSystemEventHandler(OnChanged);

            // Begin watching.
            watcher.EnableRaisingEvents = true;
        }


        //public static void Run(string path)
        //{            
        //    FileSystemWatcher watcher = new FileSystemWatcher();
        //    watcher.Path = path;

        //    /* Watch for changes in LastAccess and LastWrite times, and
        //       the renaming of files or directories. */
        //    watcher.NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite
        //       | NotifyFilters.FileName | NotifyFilters.DirectoryName;
            
        //    // Only watch text files.
        //    //watcher.Filter = "*.txt";

        //    // Add event handlers.
        //    watcher.Changed += new FileSystemEventHandler(OnChanged);
        //    watcher.Created += new FileSystemEventHandler(OnChanged);
        //    watcher.Deleted += new FileSystemEventHandler(OnChanged);

        //    // Begin watching.
        //    watcher.EnableRaisingEvents = true;
        //    while (true) ;
        //}

        // Define the event handlers.
        private static void OnChanged(object source, FileSystemEventArgs e)
        {
            string info = "";
            // Specify what is done when a file is changed, created, or deleted.
            Console.WriteLine("File: " + e.FullPath + " " + e.ChangeType);
            // Open the stream and read it back.
            using (FileStream fs = File.Open(e.FullPath, FileMode.Open))
            {
                byte[] b = new byte[1024];
                const string SERVER_IP = "10.0.0.17";
                const int PORT = 22222;
                UTF8Encoding temp = new UTF8Encoding(true);

                while (fs.Read(b, 0, b.Length) > 0)
                {
                    info += temp.GetString(b);
                }
                info = info.Replace("\0", string.Empty);
                //var parameters = info.Split('|');
                //parameters = parameters.Take(parameters.Count() - 1).ToArray();
                TcpClient Client = new TcpClient(SERVER_IP, PORT);
                try
                {
                    if (Client.Connected)
                    {
                        Client.Client.Send(Encoding.ASCII.GetBytes(info));
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("Connection is down, exiting program.");
                    Console.WriteLine("Press any key to exit.");
                    Console.ReadKey();
                }
                Client.Close();
            }
        }
    }
}

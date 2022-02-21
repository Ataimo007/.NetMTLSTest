using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using RestSharp;

namespace TykMtls2
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Demonstrating Mutual TLS on Tyk Gateway");
            Console.WriteLine("Initiating the API Call....");
            var response = GetSupplierByRegistrationNumber("61fa7944cf7b8f00018f1ec4");
            Console.WriteLine("API Call Response: " + response.Result);
        }
        
        static async Task<string> GetSupplierByRegistrationNumber(string companyRegistrationNumber)
        {
            string regNumberUrl = System.Configuration.ConfigurationManager.AppSettings["regNumberURL"];
            var options = new RestClientOptions(regNumberUrl);
 
            System.Net.ServicePointManager.ServerCertificateValidationCallback +=
            delegate (object sender, System.Security.Cryptography.X509Certificates.X509Certificate certificate,
                                    System.Security.Cryptography.X509Certificates.X509Chain chain,
                                    System.Net.Security.SslPolicyErrors sslPolicyErrors)
            {
                return true; // **** Always accept
            };
 
            var request = new RestRequest(regNumberUrl);
            
            // Headers
            string clientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];
            request.AddHeader("ClientId", clientId);
            string clientSecret = System.Configuration.ConfigurationManager.AppSettings["AccessToken"];
            request.AddHeader("AccessToken", clientSecret);
            string organisationId = System.Configuration.ConfigurationManager.AppSettings["OrganisationId"];
            request.AddHeader("OrganisationId", organisationId);
            string version = System.Configuration.ConfigurationManager.AppSettings["Version"];
            request.AddHeader("Version", version);
 
            request.AddParameter("registeredNumber", companyRegistrationNumber, ParameterType.QueryString);
 
            // add certificate
            string certificatePath = System.Configuration.ConfigurationManager.AppSettings["certificatePath"];
            string certificatePassword = System.Configuration.ConfigurationManager.AppSettings["certificatePassword"];
            
            // guessing for windows
            // X509Certificate2 clientCertificate = new X509Certificate2();
            // clientCertificate.Import(certificatePath, certificatePassword, X509KeyStorageFlags.MachineKeySet);

            // for Mac
            byte[] rawData = ReadFile(certificatePath);
            X509Certificate2 clientCertificate = new X509Certificate2(rawData, certificatePassword, X509KeyStorageFlags.MachineKeySet);
            ViewCertificate(clientCertificate);

            options.ClientCertificates = new X509CertificateCollection() { clientCertificate };
            var client = new RestClient(options);

            Console.WriteLine("Calling API Endpoint {0}", regNumberUrl);
            var response = await client.GetAsync(request, CancellationToken.None);

            // Get Request
            // IRestResponse response = options.Execute(request);
 
            return response.Content.ToString();
            // return "";
        }
        
        //Reads a file.
        private static byte[] ReadFile (string fileName)
        {
            FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            int size = (int)f.Length;
            byte[] data = new byte[size];
            size = f.Read(data, 0, size);
            f.Close();
            return data;
        }

        private static void ViewCertificate(X509Certificate2 certificate)
        {
            //Print to console information contained in the certificate.
            Console.WriteLine("{0}Subject: {1}{0}", Environment.NewLine, certificate.Subject);
            Console.WriteLine("{0}Issuer: {1}{0}", Environment.NewLine, certificate.Issuer);
            Console.WriteLine("{0}Version: {1}{0}", Environment.NewLine, certificate.Version);
            Console.WriteLine("{0}Valid Date: {1}{0}", Environment.NewLine, certificate.NotBefore);
            Console.WriteLine("{0}Expiry Date: {1}{0}", Environment.NewLine, certificate.NotAfter);
            Console.WriteLine("{0}Thumbprint: {1}{0}", Environment.NewLine, certificate.Thumbprint);
            Console.WriteLine("{0}Serial Number: {1}{0}", Environment.NewLine, certificate.SerialNumber);
            Console.WriteLine("{0}Friendly Name: {1}{0}", Environment.NewLine, certificate.PublicKey.Oid.FriendlyName);
            Console.WriteLine("{0}Public Key Format: {1}{0}", Environment.NewLine, certificate.PublicKey.EncodedKeyValue.Format(true));
            Console.WriteLine("{0}Raw Data Length: {1}{0}", Environment.NewLine, certificate.RawData.Length);
            Console.WriteLine("{0}Certificate to string: {1}{0}", Environment.NewLine, certificate.ToString(true));
            Console.WriteLine("{0}Certificate to XML String: {1}{0}", Environment.NewLine, certificate.PublicKey.Key.ToXmlString(false));

            //Add the certificate to a X509Store.
            X509Store store = new X509Store();
            store.Open(OpenFlags.MaxAllowed);
            store.Add(certificate);
            store.Close();
        }
    }
}
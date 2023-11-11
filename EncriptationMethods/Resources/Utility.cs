using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;

namespace EncriptationMethods.Resources
{
    public class Utility
    {

        public static string EncryptPassword(string password)
        {
            StringBuilder sb = new StringBuilder();

            using(SHA256 hash = SHA256.Create())
            {
                Encoding enc = Encoding.UTF8;
                byte[] result = hash.ComputeHash(enc.GetBytes(password));

                foreach (byte bite in result)
                {
                    sb.Append(bite.ToString("x2"));
                }

                return sb.ToString();
            }
        }

        public static string[] GenerateKeys()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                var publicKey = rsa.ToXmlString(false);
                var privateKey = rsa.ToXmlString(true);

                var llaves = new string[] { publicKey, privateKey };

                return llaves;
            }
        }

        public static string EncryptPasswordAsymmetrically(string password, string publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(publicKey);
                byte[] data = Encoding.UTF8.GetBytes(password);
                byte[] encryptedData = rsa.Encrypt(data, false);
                return Convert.ToBase64String(encryptedData);
            }
        }

        public static string DecryptPassword(string password, string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(privateKey);
                byte[] encryptedBytes = Convert.FromBase64String(password);
                byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, false);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
    }
}

using System.Security.Cryptography;
using System.Text;

namespace Program
{
    class RSAEncrypt
    {
        public static string EncryptWithPublicKey(string publicKeyPem,string textToEncrypt)
        {
            // 将PEM格式的公钥转换成RSA公钥对象
            using (var rsa = new RSACryptoServiceProvider())
            {
                // 去除PEM格式中的无用字符
                var publicKeyBytes = Convert.FromBase64String(publicKeyPem
                    .Replace("-----BEGIN PUBLIC KEY-----", string.Empty)
                    .Replace("-----END PUBLIC KEY-----", string.Empty)
                    .Trim());
                // 导入公钥
                rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
                // 加密文本
                var dataToEncrypt = Encoding.UTF8.GetBytes(textToEncrypt);
                var encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.Pkcs1);
                return System.Convert.ToBase64String(encryptedData);
            }
        }
    }

    class AESEncrypt
    {
        public static String GenerateKey()
        {
            string keyandIv = "";
            byte[] key = new byte[12];
            RandomNumberGenerator.Fill(key);
            byte[] iv = new byte[12];
            RandomNumberGenerator.Fill(iv);
            keyandIv = string.Format("{0}:{1}", System.Convert.ToBase64String(key), System.Convert.ToBase64String(iv));
            return keyandIv;
        }

        public static String EncryptBytes(byte[] bytesToBeEncrypted, String keyandIv)
        {
            if (bytesToBeEncrypted == null || bytesToBeEncrypted.Length <= 0)
                throw new ArgumentNullException(nameof(bytesToBeEncrypted));
            byte[] encryptedBytes;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(keyandIv.Split(":")[0]);
                aesAlg.IV = Encoding.UTF8.GetBytes(keyandIv.Split(':')[1]);
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        csEncrypt.FlushFinalBlock();
                        encryptedBytes = msEncrypt.ToArray();
                    }
                }
            }
            return System.Convert.ToBase64String(encryptedBytes);
        }

        public static string DecryptBytes(byte[] bytesToBeDecrypted, String keyandIv)
        {
            if (bytesToBeDecrypted == null || bytesToBeDecrypted.Length <= 0)
                throw new ArgumentNullException(nameof(bytesToBeDecrypted));

            byte[] decryptedBytes;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(keyandIv.Split(":")[0]);
                aesAlg.IV = Encoding.UTF8.GetBytes(keyandIv.Split(":")[1]);
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(bytesToBeDecrypted))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (MemoryStream msOutput = new MemoryStream())
                        {
                            csDecrypt.CopyTo(msOutput);
                            decryptedBytes = msOutput.ToArray();
                        }
                    }
                }
            }
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}

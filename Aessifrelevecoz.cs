using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;//şifrelemede kullanıcağımız kütüphanemiz

namespace AESencryption
{
    class Aessifrelevecoz
    {
        private const string AES_IV = @"!&+QWSDF!123126+";
        private string AesAnahtar = @"QQsaw!257()%%ert";
        AesCryptoServiceProvider Controller = new AesCryptoServiceProvider();
        public string sifrele(string metin)
        {
            Controller.BlockSize = 128;//128 bit
            Controller.KeySize = 128;
            Controller.IV = Encoding.UTF8.GetBytes(AES_IV);//UTF8 karakter türü
            Controller.Key = Encoding.UTF8.GetBytes(AesAnahtar);
            Controller.Mode = CipherMode.CBC;
            Controller.Padding = PaddingMode.PKCS7;
            byte[] giris = Encoding.Unicode.GetBytes(metin);
            using (ICryptoTransform sifrele = Controller.CreateEncryptor()) //şifreleme fonksiyonumuz
            {
                byte[] sonuc = sifrele.TransformFinalBlock(giris, 0, giris.Length);
                return Convert.ToBase64String(sonuc);
            }

        }
        public string sifreCoz(string sifreliMetin)
        {
            Controller.BlockSize = 128;//128 bit
            Controller.KeySize = 128;

            Controller.IV = Encoding.UTF8.GetBytes(AES_IV);
            Controller.Key = Encoding.UTF8.GetBytes(AesAnahtar);
            Controller.Mode = CipherMode.CBC;
            Controller.Padding = PaddingMode.PKCS7;

            byte[] giris = System.Convert.FromBase64String(sifreliMetin);
            using (ICryptoTransform decrypt = Controller.CreateDecryptor())
            {
                byte[] sonuc = decrypt.TransformFinalBlock(giris, 0, giris.Length);
                return Encoding.Unicode.GetString(sonuc);
            }

        }
    }
}

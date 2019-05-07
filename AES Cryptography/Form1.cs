using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

//This Program Creat by M.M.N

namespace AES_Cryptography
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (textBox1.Text != string.Empty && textBox2.Text != string.Empty)
            {
                var Original = Encoding.UTF8.GetBytes(textBox1.Text);
                var Password = Encoding.UTF8.GetBytes(textBox2.Text);

                Password = SHA256.Create().ComputeHash(Password);

                var Encrypt = AES_Encrypt(Original, Password);
                textBox3.Text = Convert.ToBase64String(Encrypt);
            }
            else
                MessageBox.Show("Please Fill All Requested Items !", "Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (textBox4.Text != string.Empty && textBox5.Text != string.Empty)
            {
                var Cipher = Convert.FromBase64String(textBox4.Text);
                var Password = Encoding.UTF8.GetBytes(textBox5.Text);

                Password = SHA256.Create().ComputeHash(Password);

                var Decrypt = AES_Decrypt(Cipher, Password);
                textBox6.Text = Encoding.UTF8.GetString(Decrypt);
            }
            else
                MessageBox.Show("Please Fill All Requested Items !", "Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        public static byte[] AES_Encrypt(byte[] Original_Text, byte[] Password_Text)
        {
            byte[] Encrypt_Text;
            byte[] Salt_Bytes = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (RijndaelManaged aes = new RijndaelManaged())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = 256;
                    aes.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(Password_Text, Salt_Bytes, 1000);
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    ICryptoTransform Encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, Encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(Original_Text, 0, Original_Text.Length);
                        csEncrypt.Close();
                    }

                    Encrypt_Text = msEncrypt.ToArray();
                }
            }

            return Encrypt_Text;
        }

        public static byte[] AES_Decrypt(byte[] Cipher_Text, byte[] Password_Text)
        {
            byte[] Decrypt_Text;
            byte[] Salt_Bytes = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

            using (MemoryStream msDecrypt = new MemoryStream())
            {
                using (RijndaelManaged aes = new RijndaelManaged())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = 256;
                    aes.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(Password_Text, Salt_Bytes, 1000);
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    ICryptoTransform Decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, Decryptor, CryptoStreamMode.Write))
                    {
                        csDecrypt.Write(Cipher_Text, 0, Cipher_Text.Length);
                        csDecrypt.Close();
                    }

                    Decrypt_Text = msDecrypt.ToArray();
                }
            }

            return Decrypt_Text;
        }
    }
}

using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using BC = BCrypt.Net.BCrypt;
using System.Security.Cryptography;
using System.Text;

namespace Module5_BcryptJHinojoza
{
    class Program
    {
        static void Main(string[] args)
        {           
            while (true)
            {
                Console.WriteLine("////////////////////////////////////////////");
                Console.WriteLine("Hello Password Encryptors!\n\r");
                Console.WriteLine("For symmetric key encryption type -> [symmetric]");
                Console.WriteLine("For hashing encryption type -> [hash]");
                Console.WriteLine("To end the program type -> [exit]");
                string encryptionType = Console.ReadLine();

                while (true)
                {
                    if (!encryptionType.Equals("symmetric", StringComparison.OrdinalIgnoreCase) && !encryptionType.Equals("hash", StringComparison.OrdinalIgnoreCase) && !encryptionType.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    {
                        //if invalid ask again for encryption type
                        Console.WriteLine("Please enter a valid encryption type...");
                        encryptionType = Console.ReadLine();
                    }
                    else if (encryptionType.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    {
                        //if exit then end program
                        Environment.Exit(0);
                    }
                    else
                    {
                        //exit loop if encryption is valid
                        break;
                    }
                }

                //ask for password to encrypt
                Console.WriteLine();
                Console.WriteLine("Enter a password: ");
                string password = Console.ReadLine();
                string encryptedPassword = null;

                //key for symmetric encryption
                var key = "b14ca5898a4e4133bbce2ea2315a1916";

                //encrypt password based on encryption type selected
                if (encryptionType.Equals("hash", StringComparison.OrdinalIgnoreCase))
                {
                    encryptedPassword = BC.HashPassword(password);
                }
                else if (encryptionType.Equals("symmetric", StringComparison.OrdinalIgnoreCase))
                {                   
                    encryptedPassword = EncryptString(key, password);
                }

                //show plaintext password and encrypted password
                Console.WriteLine("Entered password: " + password);
                Console.WriteLine("Encrypted password: " + encryptedPassword);
                Console.WriteLine("\n\rVeryfying You Are Who You Say You Are...");
                
                //login back with original password
                Console.WriteLine("Enter your password: ");              
                string enteredPassword = Console.ReadLine();

                //loop till right password is inputted
                while (true)
                {
                    //check hashed password
                    if (encryptionType.Equals("hash", StringComparison.OrdinalIgnoreCase) && BC.Verify(enteredPassword, encryptedPassword) == true)
                    {
                        Console.WriteLine("Succesful login!");
                        Console.WriteLine();
                        break;
                    }
                    //check symmetric password
                    else if(encryptionType.Equals("symmetric", StringComparison.OrdinalIgnoreCase) && enteredPassword.Equals(DecryptString(key, encryptedPassword)))
                    {
                        Console.WriteLine("Succesful login!");
                        Console.WriteLine();
                        break;
                    }
                    //ask user to input password again
                    else
                    {
                        Console.WriteLine("Invalid Password... retry");
                        Console.WriteLine("Enter your password: ");
                        enteredPassword = Console.ReadLine();
                    }
                }

                Console.WriteLine("Would you like to encrypt another password?(yes|no)");
                string again = Console.ReadLine();

                while (true)
                {
                    if(!again.Equals("yes", StringComparison.OrdinalIgnoreCase) && !again.Equals("no", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("Invalid input");
                        Console.WriteLine("Would you like to encrypt another password?(yes|no)");
                        again = Console.ReadLine();
                    }
                    else if(again.Equals("no", StringComparison.OrdinalIgnoreCase))
                    {
                        Environment.Exit(0);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }

        public static string EncryptString(string key, string plainText)
        {
            byte[] iv = new byte[16];
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array);
        }
        public static string DecryptString(string key, string cipherText)
        {
            byte[] iv = new byte[16];
            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(buffer))
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }

    }
}
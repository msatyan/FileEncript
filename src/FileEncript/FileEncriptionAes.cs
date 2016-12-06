using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.IO;
using System.Security.Cryptography;
using System.Text;


namespace MyAes
{
    public class MyAes
    {
        public static void Main(string[] args)
        {
            String password = null;
            String FileName = null;
            Boolean IsDecrypt = false;
            
            // Test if input arguments were supplied:
            if (args.Length != 5)
            {
                PrintUsage( "Should have 5 arguments" );
                return;
            }

            if (args[0] == "/e")
            {
                IsDecrypt = false;
            }
            else if (args[0] == "/d")
            {
                IsDecrypt = true;
            }
            else
            {
                PrintUsage("Specify /e for encript or /d for decript" );
                return;
            }

            for (int i = 1; i < 5; i+=2)
            {
                if (args[i] == "/p")
                {
                    password = args[i + 1];
                }
                else if (args[i] == "/f")
                {
                    FileName = args[i + 1];
                }
                else
                {
                    PrintUsage( "Specify passowd and filename." );
                    return;
                }
            }


            if(password == null || FileName==null)
            {
                PrintUsage("Specify passowd and filename");
                return;
            }


            Console.WriteLine("{0} With ", (IsDecrypt ? "Decrypting" : "Encripting") );
            Console.WriteLine("password  : {0}", password);
            Console.WriteLine("File Name : {0}", FileName);


            byte[] bData1 = FileToByteArray(FileName);
            byte[] bData2 = EncryptDecrypt( bData1, password, IsDecrypt);

            Console.WriteLine("bData1 length = {0}", bData1.Length);
            Console.WriteLine("bData2 length = {0}", bData2.Length);

            String NewFile = FileName + (IsDecrypt ? ".Decrypted" : ".Encripted");
            System.IO.File.WriteAllBytes(NewFile, bData2);
            Console.WriteLine();
            Console.WriteLine("The generated file is : {0}", NewFile);

        }


        public static void PrintUsage(String msg)
        {
            System.Console.WriteLine();
            System.Console.WriteLine(msg);
            System.Console.WriteLine("Please enter password and file name");
            System.Console.WriteLine("Usage: { /e or /d } /p password /f filename");
            System.Console.WriteLine("Eg:");
            System.Console.WriteLine("FileEncript.dll /e /p password1 /f filename1.xyz");
            System.Console.WriteLine("FileEncript.dll /d /p password1 /f filename1.xyz");
        }

        public static byte[] EncryptDecrypt(byte[] bData, string password, bool IsDecrypt)
        {

            Console.WriteLine("Please Wait : {0} ....", (IsDecrypt ? "Decrypting" : "Encripting"));
            // FYI: In real world scenario avoid using a constant value for 'salt'
            byte[] salt   = Encoding.ASCII.GetBytes("#MySalt+!33vs./s@&"); // salt must be at least 8 bytes

            // iterations count should be greater than zero. 
            // The minimum recommended number of iterations is 1000.
            int iterations = 2000;

            // Implements password-based key derivation functionality, 
            // PBKDF2, by using a pseudo-random number generator based on HMACSHA1.
            // The iterations, Repeatedly hash the user password along with the salt.
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);

            Aes aes = Aes.Create();
            aes.Key = pbkdf2.GetBytes(32); // set a 32*8 = 256-bit key 
            aes.IV  = pbkdf2.GetBytes(16); // set a 16*8 = 128-bit IV 

            ICryptoTransform xfrm;
            if (IsDecrypt)
            {
                xfrm = aes.CreateDecryptor();
            }
            else
            {
                xfrm = aes.CreateEncryptor();
            }

            MemoryStream ms = new MemoryStream();
            using (CryptoStream cs = new CryptoStream(ms, xfrm, CryptoStreamMode.Write))
            {
                cs.Write(bData, 0, bData.Length);
            }

            return( ms.ToArray() );
        }


        public static byte[] FileToByteArray(string FileName)
        {
            byte[] fileBytes = null;

            if (File.Exists(FileName))
            {
                fileBytes = System.IO.File.ReadAllBytes(FileName);
            }
            else
            {
                Console.WriteLine("File '{0}' not found", FileName);
            }

            return fileBytes;
        }


    }
}



// filecrypt.cs
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class FileCrypt
{
    static string Colorize(string text, string color)
    {
        string col = color switch
        {
            "green" => "\x1b[92m",
            "red" => "\x1b[91m",
            "yellow" => "\x1b[93m",
            _ => "\x1b[0m"
        };
        return col + text + "\x1b[0m";
    }

    const int SALT_LEN = 16;
    const int NONCE_LEN = 12;
    const int TAG_LEN = 16;
    const int KEY_LEN = 32;
    const int ITERATIONS = 100000;

    static byte[] DeriveKey(string password, byte[] salt)
    {
        using var rfc = new Rfc2898DeriveBytes(password, salt, ITERATIONS, HashAlgorithmName.SHA256);
        return rfc.GetBytes(KEY_LEN);
    }

    static void EncryptFile(string inputPath, string outputPath, string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SALT_LEN);
        byte[] nonce = RandomNumberGenerator.GetBytes(NONCE_LEN);
        byte[] key = DeriveKey(password, salt);

        byte[] plaintext = File.ReadAllBytes(inputPath);
        using var aes = new AesGcm(key);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TAG_LEN];
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        using var fs = new FileStream(outputPath, FileMode.Create);
        fs.Write(salt, 0, salt.Length);
        fs.Write(nonce, 0, nonce.Length);
        fs.Write(ciphertext, 0, ciphertext.Length);
        fs.Write(tag, 0, tag.Length);
        Console.WriteLine(Colorize($"File encrypted successfully: {outputPath}", "green"));
    }

    static void DecryptFile(string inputPath, string outputPath, string password)
    {
        byte[] data = File.ReadAllBytes(inputPath);
        if (data.Length < SALT_LEN + NONCE_LEN + TAG_LEN)
            throw new Exception("Invalid file format");

        byte[] salt = new byte[SALT_LEN];
        byte[] nonce = new byte[NONCE_LEN];
        Buffer.BlockCopy(data, 0, salt, 0, SALT_LEN);
        Buffer.BlockCopy(data, SALT_LEN, nonce, 0, NONCE_LEN);
        int cipherLen = data.Length - SALT_LEN - NONCE_LEN - TAG_LEN;
        byte[] ciphertext = new byte[cipherLen];
        byte[] tag = new byte[TAG_LEN];
        Buffer.BlockCopy(data, SALT_LEN + NONCE_LEN, ciphertext, 0, cipherLen);
        Buffer.BlockCopy(data, SALT_LEN + NONCE_LEN + cipherLen, tag, 0, TAG_LEN);

        byte[] key = DeriveKey(password, salt);
        using var aes = new AesGcm(key);
        byte[] plaintext = new byte[cipherLen];
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        File.WriteAllBytes(outputPath, plaintext);
        Console.WriteLine(Colorize($"File decrypted successfully: {outputPath}", "green"));
    }

    static void Main(string[] args)
    {
        if (args.Length < 4)
        {
            Console.WriteLine(Colorize("Usage: filecrypt encrypt|decrypt <input> <output> <password>", "yellow"));
            return;
        }
        string mode = args[0];
        string input = args[1];
        string output = args[2];
        string password = args[3];

        try
        {
            if (mode == "encrypt") EncryptFile(input, output, password);
            else if (mode == "decrypt") DecryptFile(input, output, password);
            else throw new Exception("Invalid mode. Use encrypt or decrypt.");
        }
        catch (Exception e)
        {
            Console.WriteLine(Colorize($"Error: {e.Message}", "red"));
        }
    }
}

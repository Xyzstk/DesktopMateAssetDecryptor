using System.Numerics;
using System.Security.Cryptography;
using System.Text;

public class Decryptor
{
    private const string keyFileName = "xriGM9Vwo1bXOkMVQPsnTw";
    private const string saltString = "uAME672YZx4q8tJ11rA2hVGaNTF1w3vEvF+lY8cvyTIroViqxgzoZXTgkFnylMXa";

    enum AssetBundleType
    {
        None,
        iltan,
        miku,
        snow_miku_2025,
        zundamon,
        Max
    }

    public static void Main(string[] args)
    {
        if (args.Length < 2) {
            Console.WriteLine("<path/to/AssetBundle/directory> <AssetBundleType(iltan/miku)> [E(Encrypt)]");
            return;
        }
        string basePath = args[0];
        string assetName = args[1];
        bool isEncrypt = args.Length >= 3 && args[2] == "E";

        AssetBundleType assetBundleType = AssetBundleType.None;
        if (!Enum.TryParse(assetName, false, out assetBundleType) || !(assetBundleType > AssetBundleType.None && assetBundleType < AssetBundleType.Max))
        {
            Console.WriteLine("Invalid AssetBundle type. Choose one of the following:");
            foreach (AssetBundleType type in Enum.GetValues(typeof(AssetBundleType)))
                if (type != AssetBundleType.None && type != AssetBundleType.Max)
                    Console.WriteLine(type.ToString());
            return;
        }

        try
        {
            Stream keyFileStream = File.OpenRead(basePath + "/" + keyFileName);
            string originalFile = args[0] + "/" + assetName;
            string encryptedFile = args[0] + "/" + SimpleAes.AesEncrypt(assetName, keyFileStream);

            string password = Encoding.UTF8.GetString(getKeyFileBytes(keyFileStream, getKeyFileOffset(keyFileStream, assetName, 3), 32));
            byte[] salt = Convert.FromBase64String(saltString);
            if (isEncrypt)
            {
                SeekableAes aesStream = new SeekableAes(File.Create(encryptedFile), password, salt, keyFileStream, (byte)assetBundleType);
                File.OpenRead(originalFile).CopyTo(aesStream);
            }
            else
            {
                SeekableAes aesStream = new SeekableAes(File.OpenRead(encryptedFile), password, salt, keyFileStream, (byte)assetBundleType);
                aesStream.CopyTo(File.Create(originalFile));
            }
        }
        catch (Exception e) {
            Console.WriteLine("Operation failed:\n" + e.ToString());
        }
    }

    public static int getKeyFileOffset(Stream fileStream, string plainText, byte charOffset)
    {
        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
        if (charOffset > 1)
        {
            for (int i = 0; i < plainTextBytes.Length; i++)
            {
                plainTextBytes[i] += charOffset;
                if (plainText != "iltan" && (i & 1) == 0)
                    plainTextBytes[i] += 2;
            }
        }
        BigInteger offset = new BigInteger(MD5.Create().ComputeHash(plainTextBytes));
        return Math.Abs((int)(offset % fileStream.Length));
    }

    public static byte[] getKeyFileBytes(Stream fileStream, int offset, int size) {
        fileStream.Seek(offset, SeekOrigin.Begin);
        byte[] res = new byte[size];
        fileStream.Read(res, 0, size);
        return res;
    }
}

public class SimpleAes
{
    public static string AesEncrypt(string plainText, Stream keyFileStream)
    {
        Aes aes = Aes.Create();
        byte[] key = Decryptor.getKeyFileBytes(keyFileStream, Decryptor.getKeyFileOffset(keyFileStream, plainText, 1), 32);
        byte[] iv = Decryptor.getKeyFileBytes(keyFileStream, Decryptor.getKeyFileOffset(keyFileStream, plainText, 7), 16);
        ICryptoTransform encryptor = aes.CreateEncryptor(key, iv);
        string encrypted;
        using (MemoryStream msEncrypt = new MemoryStream())
        {
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                }
            }
            encrypted = Convert.ToBase64String(msEncrypt.ToArray()).Replace("/", "-").Replace("=", "");
        }
        return encrypted;
    }
}

public class SeekableAes : Stream
{
    private Stream baseStream;
    private AesManaged aesData;
    private ICryptoTransform encryptor;
    public bool autoDisposeBaseStream;

    private const string key_str = "expand 32-byte key";
    private Stream KeyFileStream;
    private byte assetIdx;

    struct Key
    {
        public Key(ulong counterInit)
        {
            raw = new uint[8];
            counter = counterInit;
        }
        public uint[] raw;
        public ulong counter;
    }

    public override bool CanRead
    {
        get
        {
            return baseStream.CanRead;
        }
    }

    public override bool CanSeek
    {
        get
        {
            return baseStream.CanSeek;
        }
    }

    public override bool CanWrite
    {
        get
        {
            return baseStream.CanWrite;
        }
    }

    public override long Length
    {
        get
        {
            return baseStream.Length;
        }
    }

    public override long Position
    {
        get
        {
            return baseStream.Position;
        }
        set
        {
            baseStream.Position = value;
        }
    }

    public SeekableAes(Stream rawStream, string password, byte[] salt, Stream keyFileStream, byte assetIdx)
    {
        baseStream = rawStream;
        autoDisposeBaseStream = true;
        Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(password, salt, 2, HashAlgorithmName.SHA512);
        aesData = new AesManaged();
        aesData.KeySize = 256;
        aesData.Mode = CipherMode.ECB;
        aesData.Padding = PaddingMode.None;
        aesData.Key = rfc.GetBytes(32);
        encryptor = aesData.CreateEncryptor();
        KeyFileStream = keyFileStream;
        this.assetIdx = assetIdx;
    }

    void ror_int128(uint[] value, int byte_cnt)
    {
        for (int i = 0; i < byte_cnt; i++)
        {
            uint tmp = value[0];
            value[0] = value[1];
            value[1] = value[2];
            value[2] = value[3];
            value[3] = tmp;
        }
    }

    private void rotate_enc(uint[][] buf)
    {
        for (int i = 0; i < 4; i++)
        {
            buf[0][i] += buf[1][i];
            buf[3][i] = BitOperations.RotateLeft(buf[3][i] ^ buf[0][i], 16);
            buf[2][i] += buf[3][i];
            buf[1][i] = BitOperations.RotateLeft(buf[1][i] ^ buf[2][i], 12);
            buf[0][i] += buf[1][i];
            buf[3][i] = BitOperations.RotateLeft(buf[3][i] ^ buf[0][i], 8);
            buf[2][i] += buf[3][i];
            buf[1][i] = BitOperations.RotateLeft(buf[1][i] ^ buf[2][i], 7);
        }
    }

    private byte[] parse_key(ref Key key, int loopCnt)
    {
        byte[] res = new byte[0x100];
        uint[] strkey = new uint[4];
        Buffer.BlockCopy(Encoding.UTF8.GetBytes(key_str), 0, strkey, 0, 16);
        uint[][] buf = new uint[4][];
        for (int i = 0; i < 4; i++)
            buf[i] = new uint[4];
        for (int i = 0; i < 4; i++)
        {
            uint[] parsed = new uint[16];
            for (int j = 0; j < 4; j++)
            {
                parsed[j] = buf[0][j] = strkey[j];
                parsed[j + 4] = buf[1][j] = key.raw[j];
                parsed[j + 8] = buf[2][j] = key.raw[j + 4];
                parsed[j + 12] = buf[3][j] = (uint)((UInt128)key.counter >> (32 * j));
            }
            for (int j = 0; j < loopCnt; j++)
            {
                rotate_enc(buf);
                ror_int128(buf[1], 1);
                ror_int128(buf[2], 2);
                ror_int128(buf[3], 3);
                rotate_enc(buf);
                ror_int128(buf[1], 3);
                ror_int128(buf[2], 2);
                ror_int128(buf[3], 1);
            }
            for (int j = 0; j < 4; j++)
                for (int k = 0; k < 4; k++)
                    parsed[j * 4 + k] += buf[j][k];
            Buffer.BlockCopy(parsed, 0, res, i * 64, 64);
            key.counter++;
        }
        return res;
    }

    private void crypto(byte[] buffer, int count, long streamPos)
    {
        Key key = new Key(0);
        ulong value = assetIdx + 0x676A3E970301B49Du;
        for (int i = 0; i < 8; i++)
        {
            value = 0x5851F42D4C957F2Du * value - 0x5E89AB1B9041E80Du;
            key.raw[i] = BitOperations.RotateRight((uint)((value >> 27) ^ (value >> 45)), (int)(value >> 59));
        }
        byte[] parsed_key = parse_key(ref key, 4);
        byte[] keyBlock = new byte[0x7F7];
        UInt128 filePos = (UInt128)BitConverter.ToUInt64(parsed_key, 0) * (UInt128)(KeyFileStream.Length - 0x7F7);
        if (0x7F7u - (ulong)KeyFileStream.Length < (ulong)filePos)
            filePos += ((UInt128)BitConverter.ToUInt64(parsed_key, 8) * (UInt128)(KeyFileStream.Length - 0x7F7)) >> 64;
        KeyFileStream.Seek((long)(filePos >> 64), SeekOrigin.Begin);
        KeyFileStream.Read(keyBlock, 0, 0x7F7);
        key.counter = (ulong)streamPos / 0x650;
        parsed_key = parse_key(ref key, 4);
        long keyPos = (streamPos / 101) & 0xF;
        for (int i = 0; i < count; i++, streamPos++)
        {
            buffer[i] ^= parsed_key[keyPos * 4];
            buffer[i] ^= keyBlock[streamPos % 0x7F7];
            if (streamPos % 101 == 100)
            {
                if (++keyPos >= 0x40)
                {
                    parsed_key = parse_key(ref key, 4);
                    keyPos = 0;
                }
            }
        }
    }

    private void cipher(byte[] buffer, int offset, int count, long streamPos)
    {
        int size = aesData.BlockSize / 8;
        byte[] srcblock = new byte[size];
        byte[] dstblock = new byte[size];
        var blockoff = streamPos % size;
        var blockidx = streamPos / size + 1;
        bool flag = false;
        while (offset < count) {
            if(!flag || blockoff % size == 0)
            {
                BitConverter.GetBytes(blockidx).CopyTo(srcblock, 0);
                encryptor.TransformBlock(srcblock, 0, size, dstblock, 0);
                blockidx++;
                if(flag) blockoff = 0;
                flag = true;
            }
            buffer[offset++] ^= dstblock[blockoff++];
        }
    }

    public override void Flush()
    {
        baseStream.Flush();
    }

    public override void SetLength(long value)
    {
        baseStream.SetLength(value);
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        return baseStream.Seek(offset, origin);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var pos = Position;
        int res = baseStream.Read(buffer, offset, count);
        cipher(buffer, offset, count, pos);
        crypto(buffer, count, pos);
        return res;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        crypto(buffer, count, Position);
        cipher(buffer, offset, count, Position);
        baseStream.Write(buffer, offset, count);
    }

    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            encryptor.Dispose();
            aesData.Dispose();
            if(autoDisposeBaseStream) baseStream.Dispose();
        }
    }
}

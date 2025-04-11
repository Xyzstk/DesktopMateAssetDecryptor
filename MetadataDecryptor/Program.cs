public class MetadataDecryptor
{
    private const int headerSize = 0x150;
    private const byte headerKey = 0x50;
    struct BlockInfo
    {
        public BlockInfo(int _valEntry, int _sizeEntry, int _offset1, int _offset2, bool _sign)
        {
            valEntry = _valEntry;
            sizeEntry = _sizeEntry;
            offset1 = _offset1;
            offset2 = _offset2;
            sign = _sign;
        }
        public int valEntry;
        public int sizeEntry;
        public int offset1;
        public int offset2;
        public bool sign;
    }
    private static readonly BlockInfo[] encryptedBlocks = {
        new BlockInfo(0x38, 0xC0, -0x1C, -0x20, false),
        new BlockInfo(0x14, 0x104, -0x3C, -0x20, false),
        new BlockInfo(0x114, 0x34, -0x14, 0x20, true),
        new BlockInfo(0x8, 0xD0, -0x28, 0x20, true),
        new BlockInfo(0xFC, 0xF8, 0x24, -0x20, false),
        new BlockInfo(0x28, 0x18, -0x30, 0x20, true),
        new BlockInfo(0x10, 0, 0x18, 0x20, true)
    };
    private static readonly (int, int)[] vectorOffset =
    {
        (0x30, -0x28),
        (0x60, -0x18),
        (0x3C, -0x14),
        (0xD4, -0x34),
        (0xAC, -0x14),
        (0x68, -0x38),
        (0x48, -0x30),
        (0x12C, 0x1C),
        (0x9C, -0x18),
        (0xF4, 0x38),
        (0x20, -0x3C),
        (0x58, 0x3C),
        (0xB0, 0x24),
        (0xDC, -0x28),
        (0x11C, 0x28),
        (0xC8, 0x20),
        (0x13C, 0x1C),
        (0xBC, 0x20),
        (0x8C, -0x30),
        (0x38, -0x1C),
        (0x14, -0x3C),
        (0x114, -0x14),
        (0x8, -0x28),
        (0xFC, 0x24),
        (0x28, -0x30),
        (0x10, 0x18),
        (0x44, -0x38),
        (0x54, 0x10),
        (0xE8, 0x20),
        (0x140, -0x24),
        (0x10C, 0x34),
    };
    public static void Main(string[] args)
    {
        if (args.Length < 2) return;
        try
        {
            Stream fileStream = File.Create(args[1]);
            Stream encryptedFileStream = File.OpenRead(args[0]);
            // Decrypt header
            byte[] headerRaw = new byte[headerSize];
            encryptedFileStream.Seek(0, SeekOrigin.Begin);
            encryptedFileStream.Read(headerRaw, 0, headerSize);
            for(int i = 0; i < headerSize; i++)
            {
                headerRaw[i] ^= (byte)(headerKey - (i & 0xFF));
            }
            int[] header = new int[headerSize >> 2];
            for (int i = 0; i < header.Length; i++)
                header[i] = BitConverter.ToInt32(headerRaw, i * 4);
            // Reserve space for the header
            fileStream.Seek(0x100, SeekOrigin.Begin);
            encryptedFileStream.CopyTo(fileStream);
            encryptedFileStream.Close();
            // Decrypt blocks
            for(int i = 0; i < encryptedBlocks.Length; i++)
            {
                BlockInfo block = encryptedBlocks[i];
                decryptBlock(fileStream, header[block.valEntry >> 2], header[block.sizeEntry >> 2], block.offset1, block.offset2, block.sign);
            }
            // Rebuild header
            int[] blockVectors = vectorOffset.Select(v => header[v.Item1 >> 2] + v.Item2 + 0x100 - headerSize).ToArray();
            Array.Sort(blockVectors);
            int[] newHeader = new int[64];
            newHeader[0] = unchecked((int)0xFAB11BAF);
            newHeader[1] = 29;
            for (int i = 0; i < blockVectors.Length; i++)
            {
                newHeader[i * 2 + 2] = blockVectors[i];
                newHeader[i * 2 + 3] = (i == blockVectors.Length - 1 ? (int)fileStream.Length : blockVectors[i + 1]) - blockVectors[i];
            }
            byte[] newHeaderRaw = new byte[0x100];
            Buffer.BlockCopy(newHeader, 0, newHeaderRaw, 0, 0x100);
            fileStream.Seek(0, SeekOrigin.Begin);
            fileStream.Write(newHeaderRaw);
            fileStream.Close();
        }
        catch (Exception e)
        {
            Console.WriteLine("Operation failed:\n" + e.ToString());
        }
    }

    public static void decryptBlock(Stream fileStream, int addr, int size, int offset1, int offset2, bool sign)
    {
        byte[] buf = new byte[size];
        int fileOffset = addr + offset1 + 0x100 - headerSize;
        fileStream.Seek(fileOffset, SeekOrigin.Begin);
        fileStream.Read(buf, 0, size);
        for (int i = 0; i < size; i++)
        {
            buf[i] ^= (byte)(size * (sign ? -1 : 1) + i + offset2);
        }
        fileStream.Seek(fileOffset, SeekOrigin.Begin);
        fileStream.Write(buf, 0, size);
    }
}

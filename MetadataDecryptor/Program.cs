using System.Diagnostics;

public class MetadataDecryptor
{
    private const int headerSize = 0x324;
    private const int blockKey = -1;
    struct BlockInfo
    {
        public BlockInfo(int _valEntry, int _sizeEntry, int _offset, bool _sign)
        {
            valEntry = _valEntry;
            sizeEntry = _sizeEntry;
            offset = _offset;
            sign = _sign;
        }
        public int valEntry;
        public int sizeEntry;
        public int offset;
        public bool sign;
    }
    private static readonly BlockInfo[] encryptedBlocks = {
        new BlockInfo(0x244, 0x248, -0x18, false),
        new BlockInfo(0x19C, 0x1A0, 0x28, false),
        new BlockInfo(0x274, 0x278, -0x10, false),
        new BlockInfo(0x64, 0x68, -0x18, true),
        new BlockInfo(0x1E4, 0x1E8, 0x28, true),
        new BlockInfo(0x2D4, 0x2D8, -0x24, true),
        new BlockInfo(0x94, 0x98, -0x28, true)
    };
    private static readonly (int, int)[] vectorOffset =
    {
        (0x13C, -0x30),
        (0x304, 0x20),
        (0xC4, -0x2C),
        (0x28, 0x38),
        (0x244, -0x18),
        (0x19C, 0x28),
        (0x274, -0x10),
        (0x64, -0x18),
        (0x1E4, 0x28),
        (0x2D4, -0x24),
        (0x94, -0x28),
        (0x1FC, 0x1C),
        (0x25C, 0x3C),
        (0xB8, -0x34),
        (0x178, 0x3C),
        (0x2F8, 0x1C),
        (0x40, 0x2C),
        (0x4, -0x18),
        (0xD0, -0x28),
        (0x148, 0x28),
        (0x58, 0x3C),
        (0x238, -0x18),
        (0x4C, 0x1C),
        (0xA0, 0x18),
        (0x22C, -0x28),
        (0x2BC, 0x24),
        (0x2E0, -0x18),
        (0x88, 0x18),
        (0x184, 0x34),
        (0x31C, -0x1C),
        (0x100, -0x28)
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
                headerRaw[i] ^= (byte)(~i & 0xFF);
            }
            int[] header = new int[headerSize >> 2];
            for (int i = 0; i < header.Length; i++)
                header[i] = BitConverter.ToInt32(headerRaw, i * 4);
            // Reserve space for the header
            fileStream.Seek(0x17C, SeekOrigin.Begin);
            encryptedFileStream.CopyTo(fileStream);
            encryptedFileStream.Close();
            // Decrypt blocks
            for(int i = 0; i < encryptedBlocks.Length; i++)
            {
                BlockInfo block = encryptedBlocks[i];
                decryptBlock(fileStream, header[block.valEntry >> 2], header[block.sizeEntry >> 2], block.offset, block.sign);
            }
            // Rebuild header
            int[] blockVectors = vectorOffset.Select(v => header[v.Item1 >> 2] + v.Item2 + 0x17C - headerSize).ToArray();
            Array.Sort(blockVectors);
            int[] newHeader = new int[95];
            newHeader[0] = unchecked((int)0xFAB11BAF);
            newHeader[1] = 39;
            for (int i = 0; i < blockVectors.Length; i++)
            {
                newHeader[i * 3 + 2] = blockVectors[i];
                newHeader[i * 3 + 3] = (i == blockVectors.Length - 1 ? (int)fileStream.Length : blockVectors[i + 1]) - blockVectors[i];
                if (!header.Contains(newHeader[i * 3 + 3]))
                    Console.WriteLine($"Warning: size not found in header at i = {i}");
            }
            // Calculate the item counts for v38+ metadata
            // First we need to get type index width from imageOffsets section
            // assume offset value not too large, we can locate the position of INT32s from contiguous null bytes
            byte[] buf = new byte[10];
            fileStream.Seek(newHeader[56], SeekOrigin.Begin);
            fileStream.Read(buf, 0, 10);
            int Int32Pos = -1;
            for (int i = 0; i < 8; i++)
            {
                if (buf[i] == 0 && buf[i + 1] == 0)
                {
                    if (buf[i + 2] == 0)
                        Int32Pos = i - 1;
                    else
                        Int32Pos = i - 2;
                    break;
                }
            }
            int TypeIndexWidth = Int32Pos switch
            {
                0 or 4 => 4,
                1 or 6 => 1,
                2 => 2,
                _ => throw new Exception("Failed to get TypeIndexWidth!")
            };
            // ...and then calculate the element counts from this
            getElementCounts(newHeader, TypeIndexWidth);
            byte[] newHeaderRaw = new byte[0x17C];
            Buffer.BlockCopy(newHeader, 0, newHeaderRaw, 0, 0x17C);
            fileStream.Seek(0, SeekOrigin.Begin);
            fileStream.Write(newHeaderRaw);
            fileStream.Close();
        }
        catch (Exception e)
        {
            Console.WriteLine("Operation failed:\n" + e.ToString());
        }
    }

    public static void decryptBlock(Stream fileStream, int addr, int size, int offset, bool sign)
    {
        byte[] buf = new byte[size];
        int fileOffset = addr + offset + 0x17C - headerSize;
        fileStream.Seek(fileOffset, SeekOrigin.Begin);
        fileStream.Read(buf, 0, size);
        for (int i = 0; i < size; i++)
        {
            buf[i] ^= (byte)((size + blockKey) * (sign ? -1 : 1) + i);
        }
        fileStream.Seek(fileOffset, SeekOrigin.Begin);
        fileStream.Write(buf, 0, size);
    }

    private static int GetIndexWidth(int count)
    {
        return count switch
        {
            <= byte.MaxValue => sizeof(byte),
            <= ushort.MaxValue => sizeof(ushort),
            _ => sizeof(int)
        };
    }

    public static void getElementCounts(int[] header, int TypeIndexWidth)
    {
        // Get all the dynamic index widths first
        int ParameterDefinitionCount = header[33] / (2 * sizeof(int) + TypeIndexWidth);
        header[34] = ParameterDefinitionCount;
        int ParameterDefinitionIndexWidth = GetIndexWidth(ParameterDefinitionCount);
        int GenericContainerCount = header[45] / (4 * sizeof(int));
        header[46] = GenericContainerCount;
        int GenericContainerIndexWidth = GetIndexWidth(GenericContainerCount);
        int TypeDefinitionCount = header[60] / (13 * sizeof(int) + 8 * sizeof(short) + 3 * TypeIndexWidth + GenericContainerIndexWidth);
        header[61] = TypeDefinitionCount;
        int TypeDefinitionIndexWidth = GetIndexWidth(TypeDefinitionCount);
        // Calculate the remaining section element counts
        // images
        header[64] = header[63] / (8 * sizeof(int) + 2 * TypeDefinitionIndexWidth);
        // assemblies
        header[67] = header[66] / (15 * sizeof(int) + sizeof(long));
        // interface offsets
        header[58] = header[57] / (sizeof(int) + TypeIndexWidth);
        // vtable methods
        header[55] = header[54] / sizeof(int);
        // methods
        header[19] = header[18] / (3 * sizeof(int) + 4 * sizeof(short) + TypeIndexWidth + TypeDefinitionIndexWidth + GenericContainerIndexWidth + ParameterDefinitionIndexWidth);
        // fields
        header[37] = header[36] / (2 * sizeof(int) + TypeIndexWidth);
        // field default values
        header[25] = header[24] / (2 * sizeof(int) + TypeIndexWidth);
        // parameter default values
        header[22] = header[21] / (2 * sizeof(int) + TypeIndexWidth);
        // properties
        header[16] = header[15] / (5 * sizeof(int));
        // interfaces
        header[52] = header[51] / TypeIndexWidth;
        // nested types
        header[49] = header[48] / sizeof(int);
        // events
        header[13] = header[12] / (5 * sizeof(int) + TypeIndexWidth);
        // generic parameters
        header[40] = header[39] / (sizeof(int) + 4 * sizeof(short) + GenericContainerIndexWidth);
        // generic parameter constraints
        header[43] = header[42] / TypeIndexWidth;
        // referenced assemblies
        header[73] = header[72] / sizeof(int);
        // string literal
        header[4] = header[3] / sizeof(int);
        // exported types
        header[94] = header[93] / sizeof(int);
        // field references
        header[70] = header[69] / (sizeof(int) + TypeIndexWidth);
        // attribute data range
        header[79] = header[78] / (2 * sizeof(int));
        // The following element counts are not used by Cpp2IL, and are not guaranteed to be correct.
        // field and parameter default value data
        header[28] = header[27];
        // field marshaled sizes
        header[31] = header[30] / sizeof(int);
        // attribute data
        header[76] = header[75];
        // unresolved virtual call parameter types
        header[82] = header[81] / TypeIndexWidth;
        // unresolved virtual call parameter ranges
        header[85] = header[84] / (2 * sizeof(int));
    }
}

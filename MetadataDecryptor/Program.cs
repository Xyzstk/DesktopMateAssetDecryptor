using System.Diagnostics;

public class MetadataDecryptor
{
    private const int headerSize = 0x264;
    private const byte headerKey = 0x7C;
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
        new BlockInfo(0x188, 0x180, 0x20, -0x53, true),
        new BlockInfo(0x1F4, 0x1EC, -0x28, 0x53, false),
        new BlockInfo(0x50, 0x48, -0x10, -0x53, true),
        new BlockInfo(0x254, 0x24C, -0x40, 0x53, false),
        new BlockInfo(0x23C, 0x234, 0x28, -0x53, true),
        new BlockInfo(0x218, 0x210, -0x30, 0x53, false),
        new BlockInfo(0x1B8, 0x1B0, -0x2C, 0x53, false)
    };
    private static readonly (int, int)[] vectorOffset =
    {
        (0x1E8, -0x40),
        (0xD4, 0x38),
        (0x44, 0x40),
        (0x1AC, -0x24),
        (0x188, 0x20),
        (0x1F4, -0x28),
        (0x50, -0x10),
        (0x254, -0x40),
        (0x23C, 0x28),
        (0x218, -0x30),
        (0x1B8, -0x2C),
        (0x170, -0x40),
        (0xB0, 0x40),
        (0x200, -0x28),
        (0xF8, 0x30),
        (0x164, 0x40),
        (0x158, 0x38),
        (0x134, 0x1C),
        (0x194, 0x1C),
        (0x74, 0x10),
        (0x5C, 0x14),
        (0x17C, -0x2C),
        (0x1A0, 0x18),
        (0x11C, -0x40),
        (0x104, -0x18),
        (0x14C, 0x1C),
        (0x8, 0x3C),
        (0x8C, -0x28),
        (0x80, -0x34),
        (0x38, 0x18),
        (0xE0, -0x20),
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
                headerRaw[i] ^= (byte)((i & 0xFF) + headerKey);
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
                decryptBlock(fileStream, header[block.valEntry >> 2], header[block.sizeEntry >> 2], block.offset1, block.offset2, block.sign);
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

    public static void decryptBlock(Stream fileStream, int addr, int size, int offset1, int offset2, bool sign)
    {
        byte[] buf = new byte[size];
        int fileOffset = addr + offset1 + 0x17C - headerSize;
        fileStream.Seek(fileOffset, SeekOrigin.Begin);
        fileStream.Read(buf, 0, size);
        for (int i = 0; i < size; i++)
        {
            buf[i] ^= (byte)(size * (sign ? -1 : 1) + i + offset2);
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

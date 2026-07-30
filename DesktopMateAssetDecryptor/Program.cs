using System.Reflection;
using System.Security.Cryptography;
using AssetsTools.NET;
using AssetsTools.NET.Extra;
using CommandLine;

public class Options
{
    [Value(0, MetaName = "input", HelpText = "File to process, for example character.cb")]
    public required string inputFile {  get; set; }
    [Option('o', "output", Required = false, HelpText = "Output file")]
    public string? outputFile { get; set; }
    [Option('e', "encrypt", Required = false, HelpText = "Encrypt the input file into .cb asset bundle")]
    public bool isEncrypt { get; set; }
    [Option('v', "file-version", Required = false, HelpText = "File version to set in the encrypted asset bundle. Need to be identical to the version specified in database.info.")]
    public int? fileVersion { get; set; }
    [Option('m', "decrypt-mesh", Required = false, HelpText = "Decrypt the mesh in the asset bundle. Should be enabled for all dlc characters.")]
    public bool decryptMesh { get; set; }
}

public class MeshHelper
{
    private List<AssetTypeValueField> channelInfo;
    private Dictionary<int, int> streamItemSize;
    private Dictionary<int, int> streamBaseOffset;
    private byte[] data;
    public uint vertexCount;

    public MeshHelper(AssetTypeValueField vertexData)
    {
        channelInfo = vertexData["m_Channels"]["Array"].Children;
        data = vertexData["m_DataSize"].AsByteArray;
        vertexCount = vertexData["m_VertexCount"].AsUInt;
        streamItemSize = new Dictionary<int, int>();
        streamBaseOffset = new Dictionary<int, int>();
        for (int i = 0; i < channelInfo.Count; i++)
        {
            byte stream = channelInfo[i]["stream"].AsByte;
            if (!streamItemSize.ContainsKey(stream)) streamItemSize.Add(stream, 0);
            streamItemSize[stream] += channelInfo[i]["dimension"].AsByte * (channelInfo[i]["format"].AsByte switch
            {
                0 or 10 or 11 => 4,
                2 or 3 or 6 or 7 => 1,
                _ => 2
            });
        }
        streamBaseOffset.Add(0, 0);
        for (int i = 1; i < streamItemSize.Count; i++) streamBaseOffset.Add(i, (streamBaseOffset[i - 1] + (int)(streamItemSize[i - 1] * vertexCount) + 0xF) & ~0xF);
    }
    public float ReadFloat32(int channel, int index, int dimension)
    {
        byte stream = channelInfo[channel]["stream"].AsByte;
        return BitConverter.ToSingle(data, streamBaseOffset[stream] + streamItemSize[stream] * index + channelInfo[channel]["offset"].AsByte + 4 * dimension);
    }

    public void WriteFloat32(int channel, int index, int dimension, float value)
    {
        byte stream = channelInfo[channel]["stream"].AsByte;
        BitConverter.TryWriteBytes(data.AsSpan(streamBaseOffset[stream] + streamItemSize[stream] * index + channelInfo[channel]["offset"].AsByte + 4 * dimension), value);
    }
}

public class Decryptor
{
    private const string aesKey = "TyJripS/Hy9NRQp7/6Spjw==";
    public static void Main(string[] args)
    {
        Options opts = Parser.Default.ParseArguments<Options>(args)
            .WithNotParsed(error => { Environment.Exit(1); })
            .Value;
        try
        {
            if (opts.isEncrypt)
            {
                if (opts.fileVersion == null)
                {
                    Console.WriteLine("Error: File version is not provided!");
                    Console.WriteLine("Hint: You can use the file version from the console output when decrypting asset bundle of the target character.");
                    Environment.Exit(1);
                }
                if (opts.outputFile == null)
                    opts.outputFile = Path.ChangeExtension(opts.inputFile, ".cb");
                Stream outputFile = File.Create(opts.outputFile);
                outputFile.Write(BitConverter.GetBytes(0x33764243));
                outputFile.Write(BitConverter.GetBytes(0x14C));
                byte[] xorKey = new byte[0x100];
                RandomNumberGenerator.Fill(xorKey);
                outputFile.Write(xorKey, 0, 0x100);
                outputFile.Seek(0x10C, SeekOrigin.Begin);
                outputFile.Write(BitConverter.GetBytes(opts.fileVersion.Value));
                using SeekableAes aesStream = new SeekableAes(outputFile, 0x14C, Convert.FromBase64String(aesKey), xorKey);
                aesStream.Seek(0, SeekOrigin.Begin);
                File.OpenRead(opts.inputFile).CopyTo(aesStream);
                Console.WriteLine($"Saved encrypted asset bundle to {opts.outputFile}");
            }
            else
            {
                Stream encryptedFile = File.OpenRead(opts.inputFile);
                if (opts.outputFile == null)
                    opts.outputFile = Path.ChangeExtension(opts.inputFile, ".unity3d");
                encryptedFile.Seek(4, SeekOrigin.Begin);
                byte[] buf = new byte[0x10C];
                encryptedFile.Read(buf, 0, buf.Length);
                using SeekableAes aesStream = new SeekableAes(encryptedFile, BitConverter.ToUInt32(buf, 0), Convert.FromBase64String(aesKey), buf[4..0x104]);
                Console.WriteLine($"File version: {BitConverter.ToInt32(buf, 0x108)}");
                byte[] meshKey = buf[0x104..0x108];
                byte[] keys = new byte[0x800];
                Stream? keyStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("DesktopMateAssetDecryptor.keys.bin");
                if (keyStream == null) throw new Exception("Failed to read keys");
                keyStream.Read(keys, 0, keys.Length);
                uint key0 = BitConverter.ToUInt32(keys, (meshKey[0] ^ meshKey[1] ^ meshKey[2] ^ meshKey[3]) << 2);
                uint key1 = BitConverter.ToUInt32(keys, (meshKey[0] << 2) + 0x400);
                uint[] finalMeshKey =
                [
                    BitConverter.ToUInt16(meshKey, 0) ^ (key1 & 0xFFFF),
                    BitConverter.ToUInt16(meshKey, 2) ^ (key1 >> 16),
                    BitConverter.ToUInt16(meshKey, 1) ^ (key0 & 0xFFFF),
                    (uint)((meshKey[1] << 8) | meshKey[3]) ^ (key0 >> 16),
                ];
                if (opts.decryptMesh)
                {
                    var manager = new AssetsManager();
                    var bundle = manager.LoadBundleFile(aesStream, opts.outputFile);
                    var collectionInst = manager.LoadAssetsFileFromBundle(bundle, 0);
                    var collection = collectionInst.file;
                    foreach (var mesh in collection.GetAssetsOfType(AssetClassID.Mesh))
                    {
                        var meshBase = manager.GetBaseField(collectionInst, mesh);
                        MeshHelper meshHelper = new MeshHelper(meshBase["m_VertexData"]);
                        for (int i = 0; i < meshHelper.vertexCount; i++)
                        {
                            uint x = (uint)(meshHelper.ReadFloat32(11, i, 0) * 256.0f + 0.5f);
                            x = ((x ^ (x >> 16)) * 0x7FEB352D) ^ finalMeshKey[0];
                            x = ((x ^ (x >> 13)) * 0xC2B2AE35) ^ finalMeshKey[1];
                            x = ((x ^ (x >> 16)) * 0x6B2B79A9) ^ finalMeshKey[2];
                            x = ((x ^ (x >> 13)) * 0xB5AD4EC3) ^ finalMeshKey[3];
                            x = ((x ^ (x >> 16)) * 0x1B873593) & 0xFF;
                            for (int d = 0; d < 3; d++) meshHelper.WriteFloat32(0, i, d, meshHelper.ReadFloat32(0, i, d) - meshHelper.ReadFloat32(1, i, d) * x / 256.0f);
                        }
                        mesh.SetNewData(meshBase);
                    }
                    foreach (var material in collection.GetAssetsOfType(AssetClassID.Material))
                    {
                        var materialBase = manager.GetBaseField(collectionInst, material);
                        var properties = materialBase["m_SavedProperties"]["m_Floats"]["Array"].Children;
                        for (int i = 0; i < properties.Count; i++)
                        {
                            if (properties[i]["first"].AsString.Equals("_DmIgnoreEncryption"))
                            {
                                properties[i]["second"].AsFloat = 1.0f;
                                material.SetNewData(materialBase);
                                break;
                            }
                        }
                    }
                    bundle.file.BlockAndDirInfo.DirectoryInfos[0].SetNewData(collection);
                    using MemoryStream outputStream = new MemoryStream();
                    using var bundleWriter = new AssetsFileWriter(outputStream);
                    bundle.file.Write(bundleWriter);
                    outputStream.Position = 0;
                    var outputBundle = new AssetBundleFile();
                    outputBundle.Read(new AssetsFileReader(outputStream));
                    using var compressedWriter = new AssetsFileWriter(opts.outputFile);
                    Console.WriteLine("Compressing asset bundle...");
                    outputBundle.Pack(compressedWriter, bundle.originalCompression);
                } else
                {
                    Console.WriteLine($"Mesh keys: {finalMeshKey[0]} {finalMeshKey[1]} {finalMeshKey[2]} {finalMeshKey[3]}");
                    Console.WriteLine("Hint: If the model appears to be corrupted, set the Keys field of relavant materials with the mesh keys; or use -m (--decrypt-mesh) to decrypt the mesh directly.");
                    aesStream.CopyTo(File.Create(opts.outputFile));
                }
                Console.WriteLine($"Saved decrypted asset bundle to {opts.outputFile}");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Operation failed:\n" + e.ToString());
        }
    }
}

public class SeekableAes : Stream
{
    private Stream baseStream;
    private Aes aes;
    private ICryptoTransform encryptor;
    private byte[] xorKey;
    private uint startOffset;
    public bool autoDisposeBaseStream;

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
            return baseStream.Position - startOffset;
        }
        set
        {
            baseStream.Position = value + startOffset;
        }
    }

    public SeekableAes(Stream rawStream, uint startOffset, byte[] aesKey, byte[] xorKey)
    {
        rawStream.Seek(startOffset, SeekOrigin.Begin);
        baseStream = rawStream;
        autoDisposeBaseStream = true;
        this.xorKey = xorKey;
        this.startOffset = startOffset;
        aes = Aes.Create();
        aes.BlockSize = 128;
        aes.KeySize = 256;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = aesKey;
        encryptor = aes.CreateEncryptor();
    }

    private void cipher(byte[] buffer, int offset, int count, long streamPos)
    {
        int size = aes.BlockSize / 8;
        byte[] srcblock = new byte[size];
        byte[] dstblock = new byte[size];
        var blockoff = streamPos % size;
        var blockidx = streamPos / size + 1;
        count += offset;
        bool flag = false;
        while (offset < count)
        {
            if (!flag || blockoff % size == 0)
            {
                BitConverter.GetBytes((ulong)blockidx ^ BitConverter.ToUInt64(xorKey, (int)(blockidx & 0x1F)) ^ BitConverter.ToUInt64(xorKey, (int)((blockidx + 0x10) & 0x1F))).CopyTo(srcblock, 0);
                encryptor.TransformBlock(srcblock, 0, size, dstblock, 0);
                blockidx++;
                if (flag) blockoff = 0;
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
        if (origin == SeekOrigin.Begin) offset += startOffset;
        return baseStream.Seek(offset, origin) - startOffset;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var pos = Position;
        int res = baseStream.Read(buffer, offset, count);
        cipher(buffer, offset, count, pos);
        return res;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        cipher(buffer, offset, count, Position);
        baseStream.Write(buffer, offset, count);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            encryptor.Dispose();
            aes.Dispose();
            if (autoDisposeBaseStream) baseStream.Dispose();
        }
    }
}

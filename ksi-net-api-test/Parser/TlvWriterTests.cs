using System;
using System.IO;
using NUnit.Framework;

namespace Guardtime.KSI.Parser
{
    [TestFixture()]
    public class TlvWriterTests
    {
        [Test()]
        public void TestWriteTagShort()
        {
            using (var writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new RawTag(0x1, false, true, new byte[] { 0x0, 0x1, 0x2, 0x3 }));
                CollectionAssert.AreEqual(new byte[] { 0x21, 0x4, 0x0, 0x1, 0x2, 0x3 }, ((MemoryStream)writer.BaseStream).ToArray(), "Writer should output correct byte array");
            }
        }

        [Test()]
        public void TestWriteTagShortWithLongType()
        {
            using (var writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new RawTag(0x33, false, true, new byte[] { 0x0, 0x1, 0x2, 0x3 }));
                CollectionAssert.AreEqual(new byte[] { 0xa0, 0x33, 0x0, 0x4, 0x0, 0x1, 0x2, 0x3 }, ((MemoryStream)writer.BaseStream).ToArray(), "Writer should output correct byte array");
            }
        }

        [Test()]
        public void TestWriteTagLongWithShortType()
        {
            using (var writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new RawTag(0x1, true, true, new byte[256]));

                var result = new byte[260];
                result[0] = 0xe0;
                result[1] = 0x1;
                result[2] = 0x1;
                result[3] = 0x0;
                Array.Copy(new byte[256], 0, result, 4, 256);
                CollectionAssert.AreEqual(result, ((MemoryStream)writer.BaseStream).ToArray(), "Writer should output correct byte array");
            }
        }

        [Test()]
        public void TestWriteTagLongWithLongType()
        {
            using (var writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new RawTag(0x257, true, true, new byte[256]));

                var result = new byte[260];
                result[0] = 0xe2;
                result[1] = 0x57;
                result[2] = 0x1;
                result[3] = 0x0;
                Array.Copy(new byte[256], 0, result, 4, 256);
                CollectionAssert.AreEqual(result, ((MemoryStream)writer.BaseStream).ToArray(), "Writer should output correct byte array");
            }
        }

        [Test]
        public void TestWriteNullValue()
        {
            using (var stream = new MemoryStream())
            using (var writer = new TlvWriter(stream))
            {
                writer.WriteTag(new AllowNullValueTlvTag(new byte[] { 0x1, 0x0 }));
                writer.WriteTag(new AllowNullValueTlvTag(new byte[] { 0xe2, 0x57, 0x0, 0x0 }));
                Console.WriteLine(Util.Util.ConvertByteArrayToHex(stream.ToArray()));
                CollectionAssert.AreEqual(new byte[] {0x1, 0x0, 0xe2, 0x57, 0x0}, stream.ToArray(), "Writer should output correct byte array");
            }
        }

        [Test]
        public void TestWriteNullTag()
        {
            using (var writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(null);
                CollectionAssert.AreEqual(new byte[] {}, ((MemoryStream)writer.BaseStream).ToArray(), "Writer should output correct byte array");
            }
        }

        [Test(), ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void TestWriteTagWithTooLongType()
        {
            using (var writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new RawTag(0x2000, true, true, new byte[256]));
            }
        }

        [Test(), ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void TestWriteTagWithTooLongData()
        {
            using (var writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new RawTag(0x1, true, true, new byte[ushort.MaxValue + 1]));
            }
        }

        private class AllowNullValueTlvTag : TlvTag
        {
            public AllowNullValueTlvTag(byte[] bytes) : base(bytes)
            {
                
            }

            public override byte[] EncodeValue()
            {
                return null;
            }
        }
    }
}
using System;
using System.IO;
using NUnit.Framework;

namespace Guardtime.KSI.Parser
{
    [TestFixture]
    public class TlvWriterTests
    {
        [Test]
        public void TestWriteTagShort()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new RawTag(0x1, false, true, new byte[] {0x0, 0x1, 0x2, 0x3}));
                CollectionAssert.AreEqual(new byte[] {0x21, 0x4, 0x0, 0x1, 0x2, 0x3}, ((MemoryStream)writer.BaseStream).ToArray(), "Writer should output correct byte array");
            }
        }

        [Test]
        public void TestWriteTagShortWithLongType()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new RawTag(0x33, false, true, new byte[] {0x0, 0x1, 0x2, 0x3}));
                CollectionAssert.AreEqual(new byte[] {0xa0, 0x33, 0x0, 0x4, 0x0, 0x1, 0x2, 0x3}, ((MemoryStream)writer.BaseStream).ToArray(),
                    "Writer should output correct byte array");
            }
        }

        [Test]
        public void TestWriteTagLongWithShortType()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new RawTag(0x1, true, true, new byte[256]));

                byte[] result = new byte[260];
                result[0] = 0xe0;
                result[1] = 0x1;
                result[2] = 0x1;
                result[3] = 0x0;
                Array.Copy(new byte[256], 0, result, 4, 256);
                CollectionAssert.AreEqual(result, ((MemoryStream)writer.BaseStream).ToArray(), "Writer should output correct byte array");
            }
        }

        [Test]
        public void TestWriteTagLongWithLongType()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new RawTag(0x257, true, true, new byte[256]));

                byte[] result = new byte[260];
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
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new AllowNullValueTlvTag(0x1, false, false));
                writer.WriteTag(new AllowNullValueTlvTag(0x257, true, true));
                CollectionAssert.AreEqual(new byte[] {0x1, 0x0, 0xe2, 0x57, 0x0}, ((MemoryStream)writer.BaseStream).ToArray(), "Writer should output correct byte array");
            }
        }

        [Test]
        public void TestWriteNullTag()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(null);
                CollectionAssert.AreEqual(new byte[] {}, ((MemoryStream)writer.BaseStream).ToArray(), "Writer should output correct byte array");
            }
        }

        [Test]
        public void TestWriteTagWithTooLongType()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                Assert.Throws<ArgumentOutOfRangeException>(delegate
                {
                    writer.WriteTag(new RawTag(0x2000, true, true, new byte[256]));
                });
            }
        }

        [Test]
        public void TestWriteTagWithTooLongData()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                Assert.Throws<ArgumentOutOfRangeException>(delegate
                {
                    writer.WriteTag(new RawTag(0x1, true, true, new byte[ushort.MaxValue + 1]));
                });
            }
        }

        private class AllowNullValueTlvTag : TlvTag
        {
            public override byte[] EncodeValue()
            {
                return null;
            }

            public AllowNullValueTlvTag(uint type, bool nonCritical, bool forward) : base(type, nonCritical, forward)
            {
            }

            public override int GetHashCode()
            {
                throw new NotImplementedException();
            }
        }
    }
}
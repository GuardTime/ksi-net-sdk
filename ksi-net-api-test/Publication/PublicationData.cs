using System.IO;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Properties;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Guardtime.KSI.Publication
{
    [TestClass]
    public class PublicationDataTest
    {

        [TestMethod]
        public void TestPublicationDataFromTag()
        {
            var stream = new FileStream(Resources.PublicationData_CorrectStructureFile, FileMode.Open);
            var reader = new TlvReader(stream);

            var tag = new CompositeTag<PublicationData>(reader.ReadTag(), new PublicationData());

            Assert.AreEqual((uint)0x10, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
//            Assert.AreEqual("test message", tag.Value, "Tag value should be decoded correctly");
//            Assert.AreEqual("TLV[0x1]:\"test message\"", tag.ToString(), "Tag string representation should be correct");
        }

//        [TestMethod]
//        public void TestPublicationDataCreate()
//        {
//            Stream stream = new MemoryStream();
//            var writer = new TlvWriter(stream);
//
//            writer.WriteTag(new RawTag(0x2, false, false, new byte[] {0x0, 0x1}));
//            writer.WriteTag(new RawTag(0x3, false, false, new byte[] {0x0, 0x1, 0x2, 0x5}));
//            writer.WriteTag(new RawTag(0x4, false, false, new DataHash(HashAlgorithm.Sha2256, new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }).Imprint));
//
//            var data = ((MemoryStream)stream).ToArray();
//            stream.SetLength(0);
//
//            stream = new FileStream("resources/publication/publicationData/missingtag.tlv", FileMode.CreateNew);
//            writer = new TlvWriter(stream);
//
//            writer.WriteTag(new RawTag(0x10, false, false, data));
//
//
//        }
    }
}

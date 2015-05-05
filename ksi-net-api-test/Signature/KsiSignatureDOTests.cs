using Guardtime.KSI.Parser;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

namespace Guardtime.KSI.Signature.Tests.Signature
{
    [TestClass()]
    public class KsiSignatureDOTests
    {
        [TestMethod()]
        public void GetMemberTest()
        {
            byte[] data;
            using (var stream = new FileStream("resources/signature/signature-ok.tlv", FileMode.Open))
            {
                data = new byte[stream.Length];
                stream.Read(data, 0, (int)stream.Length);
            }

            using (var reader = new TlvReader(new MemoryStream(data)))
            {
                var time = Environment.TickCount;
                var i = 0;
                while (Environment.TickCount - time < 1000)
                {
                    var tag = reader.ReadTag();
                    new CompositeTag<KsiSignatureDO>(tag, new KsiSignatureDO());
                    reader.BaseStream.Position = 0;
                    i++;
                }
                Console.WriteLine(i);
            }
            
        }
    }
}
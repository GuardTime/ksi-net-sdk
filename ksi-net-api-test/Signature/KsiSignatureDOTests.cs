using System;
using System.IO;
using Guardtime.KSI.Parser;
using NUnit.Framework;

namespace Guardtime.KSI.Signature
{
    [TestFixture]
    public class KsiSignatureDoTests
    {
        [Test]
        public void GetMemberTest()
        {
            byte[] data;
            using (var stream = new FileStream("resources/signature/signature-ok.tlv", FileMode.Open))
            {
                data = new byte[stream.Length];
                stream.Read(data, 0, (int)stream.Length);
            }

            var tag = new RawTag(data);
            using (var reader = new TlvReader(new MemoryStream(data)))
            {
                var test = new KsiSignatureDo(tag);
                var time = Environment.TickCount;
                var i = 0;

                while (Environment.TickCount - time < 1000)
                {
                    test = new KsiSignatureDo(tag);
                    i++;
                }
                Console.WriteLine(i);
                Console.WriteLine(test);
            }

        }
    }
}
/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.MultiSignature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public partial class BlockSignerTests
    {
        /// <summary>
        /// Test building Merkle trees
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerMakeTreeTest(Ksi ksi)
        {
            Random random = new Random();

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            for (int k = 1; k < 30; k++)
            {
                byte[] buffer = new byte[10];

                BlockSigner blockSigner = new BlockSigner(ksi);

                for (int i = 0; i < k; i++)
                {
                    IDataHasher hasher = KsiProvider.CreateDataHasher();
                    random.NextBytes(buffer);
                    hasher.AddData(buffer);

                    blockSigner.AddDocument(hasher.GetHash(), buffer[0] % 2 == 0 ? metaData : null);
                }

                Console.WriteLine("Document count: " + k);
                Console.WriteLine("Tree: " + blockSigner.PrintTree());
            }
        }

        /// <summary>
        /// Test building Merkle trees with blinding masks
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerWithBlindingMasksMakeTreeTest(Ksi ksi)
        {
            Random random = new Random();

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            for (int k = 1; k < 30; k++)
            {
                byte[] buffer = new byte[10];

                BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

                for (int i = 0; i < k; i++)
                {
                    IDataHasher hasher = KsiProvider.CreateDataHasher();
                    random.NextBytes(buffer);
                    hasher.AddData(buffer);
                    blockSigner.AddDocument(hasher.GetHash(), metaData);
                }

                Console.WriteLine("Document count: " + k);
                Console.WriteLine("Tree: " + blockSigner.PrintTree());
            }
        }

        /// <summary>
        /// Test printing tree with 11 elements
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerPrintTree11Element7MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi);

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382")), metaData);

            Console.WriteLine("Tree: \"" + blockSigner.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                                                                                                                                                                          
                                                                                                                                                                                          5R:A9A0905  
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                          4L:B944B64                                                                                                                                                                                                  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                               \        
                                          3L:72B6A6B                                                                                      3R:29CBB88                                                                                      3R:4AAF227  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                  2L:CB1A52F                                      2R:1647806                                      2L:3AF8D26                                      2R:195B1D0                                      2L:7F0BD25                                                  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \        
      1L:11C3A77                                      1L:8A79D69              1R:6047EB7              1L:5D2A363                                                              1R:DF1D807              1L:86771B3                                      1R:24793A3  
        /    \                       \                  /    \                  /    \                  /    \                       \                  /                       /    \                  /    \                       \                  /    \        
0L:09A9FE4  0R:M:010F7              0R:BEC84E1  0L:C734EEF  0R:M:010F7  0L:B0CF0A7  0R:M:010F7  0L:BB95E9B  0R:M:010F7              0R:7943B1F  0L:23C4ADE              0L:A360BBA  0R:M:010F7  0L:0347A3E  0R:M:010F7              0R:78C6303  0L:0579A77  0R:M:010F7  
",
                blockSigner.PrintTree());
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerPrintTree5Element2MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi);

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metaData);

            Console.WriteLine("Tree: \"" + blockSigner.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                                                                          
                                                                                          4R:E04268C  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                          3L:67656B3                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                        
                  2L:CB1A52F                                      2R:BE13727                                                  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \        
      1L:11C3A77                                                                                      1R:5D2A363  
        /    \                       \                  /                            \                  /    \        
0L:09A9FE4  0R:M:010F7              0R:BEC84E1  0L:C734EEF                          0R:B0CF0A7  0L:BB95E9B  0R:M:010F7  
",
                blockSigner.PrintTree());
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerPrintTree5Element3MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi);

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + blockSigner.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                                                                          
                                                                                          4R:DFE1797  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                          3L:3D9A511                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                        
                  2L:ACD2F4B                                      2R:1647806                                                  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                
                              1R:9423D41              1L:8A79D69              1R:6047EB7                          
        /                       /    \                  /    \                  /    \           \        
0L:09A9FE4              0L:BEC84E1  0R:M:010F7  0L:C734EEF  0R:M:010F7  0L:B0CF0A7  0R:M:010F7  0R:BB95E9B  
",
                blockSigner.PrintTree());
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerPrintTree5ElementWithMetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi);

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metaData);

            Console.WriteLine("Tree: \"" + blockSigner.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                                                                          
                                                                                          4R:144393A  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                          3L:BD80B9E                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                        
                  2L:C1E4903                                      2R:1647806                                                  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \        
      1L:11C3A77              1R:9423D41              1L:8A79D69              1R:6047EB7              1R:5D2A363  
        /    \                  /    \                  /    \                  /    \                  /    \        
0L:09A9FE4  0R:M:010F7  0L:BEC84E1  0R:M:010F7  0L:C734EEF  0R:M:010F7  0L:B0CF0A7  0R:M:010F7  0L:BB95E9B  0R:M:010F7  
",
                blockSigner.PrintTree());
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerPrintTree5ElementNoMetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi);

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + blockSigner.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                                                                          
                                                                                          4R:69770A9  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                          3L:7A23D56                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                        
                  2L:9AA3A90                                      2R:BE13727                                                  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                
                                                                                                                  
        /                            \                  /                            \           \        
0L:09A9FE4                          0R:BEC84E1  0L:C734EEF                          0R:B0CF0A7  0R:BB95E9B  
",
                blockSigner.PrintTree());
        }

        /// <summary>
        /// Test printing tree with 11 elements with blindign masks
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree11Element8MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382")), metaData);

            Console.WriteLine("Tree: \"" + blockSigner.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                                                                                                                                                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                                                                                                                                                                          6R:5D3E27B  
                                                                                                                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                                                                                                                          5L:A54F551                                                                                                                                                                                                                                                                                                                                                                                                  
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                                                                                                               \        
                                                                                          4L:4DCB72B                                                                                                                                                                                      4R:7300BBF                                                                                                                                                                                      4R:818D379  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                          3L:D967F1C                                                                                      3R:603F5D3                                                                                      3L:2845CD4                                                                                      3R:7FEF78B                                                                                      3L:0935AE5                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \        
                  2L:921B9E3                                      2R:7CC3C81                                      2L:1D2BB60                                      2R:CCE2926                                      2L:3320B34                                      2R:722B85B                                      2L:67C14BD                                      2R:E3080B2                                      2L:3D13A05                                      2R:409B67E                                      2R:CFDA2A8  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                              1R:11C3A77                                                                                      1R:8A79D69                                      1R:6047EB7                                      1R:5D2A363                                      1R:270830B                                                                                                                                      1R:86771B3                                      1R:B9C5CE6                                      1R:24793A3  
        /                       /    \                  /                            \                  /                       /    \                  /                       /    \                  /                       /    \                  /                       /    \                  /                            \                  /                            \                  /                       /    \                  /                       /    \                  /                       /    \        
0L:4526CE6              0L:09A9FE4  0R:M:010F7  0L:C59F202                          0R:BEC84E1  0L:8E7123B              0L:C734EEF  0R:M:010F7  0L:25ACB7A              0L:B0CF0A7  0R:M:010F7  0L:DE99229              0L:BB95E9B  0R:M:010F7  0L:E72CC9A              0L:7943B1F  0R:M:010F7  0L:CC36E23                          0R:23C4ADE  0L:892771A                          0R:A360BBA  0L:FDE71A5              0L:0347A3E  0R:M:010F7  0L:3956D10              0L:78C6303  0R:M:010F7  0L:DA3F756              0L:0579A77  0R:M:010F7  
",
                blockSigner.PrintTree());
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5ElementAllMetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metaData);

            Console.WriteLine("Tree: \"" + blockSigner.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                                                                                                                                                                          
                                                                                                                                                                                          5R:1BBDB18  
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                          4L:0CF8522                                                                                                                                                                                                  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                        
                                          3L:A7FE656                                                                                      3R:36CBF71                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \        
                  2L:921B9E3                                      2R:5B555C9                                      2L:CBB3F93                                      2R:CCE2926                                      2R:3320B34  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                              1R:11C3A77                                      1R:9423D41                                      1R:8A79D69                                      1R:6047EB7                                      1R:5D2A363  
        /                       /    \                  /                       /    \                  /                       /    \                  /                       /    \                  /                       /    \        
0L:4526CE6              0L:09A9FE4  0R:M:010F7  0L:C59F202              0L:BEC84E1  0R:M:010F7  0L:1CB3590              0L:C734EEF  0R:M:010F7  0L:25ACB7A              0L:B0CF0A7  0R:M:010F7  0L:DE99229              0L:BB95E9B  0R:M:010F7  
",
                blockSigner.PrintTree());
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5ElementNoMetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + blockSigner.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                                                                                                                                                                          
                                                                                                                                                                                          5R:9934662  
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                          4L:6D672DE                                                                                                                                                                                                  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                        
                                          3L:655B253                                                                                      3R:DF8B1D0                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \        
                  2L:494220A                                      2R:3BC40EE                                      2L:8248411                                      2R:E515989                                      2R:715160B  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                                                                                                                                                                          
        /                            \                  /                            \                  /                            \                  /                            \                  /                \        
0L:4526CE6                          0R:09A9FE4  0L:18EF136                          0R:BEC84E1  0L:8E7123B                          0R:C734EEF  0L:7637A80                          0R:B0CF0A7  0L:A1F7F24              0R:BB95E9B  
",
                blockSigner.PrintTree());
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5Element3MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metaData);

            Console.WriteLine("Tree: \"" + blockSigner.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                                                                                                                                                                          
                                                                                                                                                                                          5R:3F88237  
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                          4L:FF9B710                                                                                                                                                                                                  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                        
                                          3L:D967F1C                                                                                      3R:0CADD33                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \        
                  2L:921B9E3                                      2R:7CC3C81                                      2L:8248411                                      2R:B409DB6                                      2R:3320B34  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                              1R:11C3A77                                                                                                                                      1R:6047EB7                                      1R:5D2A363  
        /                       /    \                  /                            \                  /                            \                  /                       /    \                  /                       /    \        
0L:4526CE6              0L:09A9FE4  0R:M:010F7  0L:C59F202                          0R:BEC84E1  0L:8E7123B                          0R:C734EEF  0L:7637A80              0L:B0CF0A7  0R:M:010F7  0L:DE99229              0L:BB95E9B  0R:M:010F7  
",
                blockSigner.PrintTree());
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5Element2MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metaData);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + blockSigner.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                                                                                                                                                                          
                                                                                                                                                                                          5R:655AA77  
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                          4L:39555AC                                                                                                                                                                                                  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                        
                                          3L:68F6464                                                                                      3R:36CBF71                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \        
                  2L:494220A                                      2R:A60A73B                                      2L:CBB3F93                                      2R:CCE2926                                      2R:4949765  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                              1R:9423D41                                      1R:8A79D69                                      1R:6047EB7                                                  
        /                            \                  /                       /    \                  /                       /    \                  /                       /    \                  /                \        
0L:4526CE6                          0R:09A9FE4  0L:18EF136              0L:BEC84E1  0R:M:010F7  0L:1CB3590              0L:C734EEF  0R:M:010F7  0L:25ACB7A              0L:B0CF0A7  0R:M:010F7  0L:DE99229              0R:BB95E9B  
",
                blockSigner.PrintTree());
        }
    }
}
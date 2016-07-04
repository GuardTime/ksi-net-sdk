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
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Test.Service;
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
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerMakeTreeTest(Ksi ksi)
        {
            Random random = new Random();

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            for (int k = 1; k < 30; k++)
            {
                byte[] buffer = new byte[10];

                BlockSigner blockSigner = new BlockSigner(ksi);

                for (int i = 0; i < k; i++)
                {
                    IDataHasher hasher = KsiProvider.CreateDataHasher();
                    random.NextBytes(buffer);
                    hasher.AddData(buffer);

                    blockSigner.AddDocument(hasher.GetHash(), buffer[0] % 2 == 0 ? metadata : null);
                }

                Console.WriteLine("Document count: " + k);
                Console.WriteLine("Tree: " + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
            }
        }

        /// <summary>
        /// Test building Merkle trees with blinding masks
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerWithBlindingMasksMakeTreeTest(Ksi ksi)
        {
            Random random = new Random();

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            for (int k = 1; k < 30; k++)
            {
                byte[] buffer = new byte[10];

                BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

                for (int i = 0; i < k; i++)
                {
                    IDataHasher hasher = KsiProvider.CreateDataHasher();
                    random.NextBytes(buffer);
                    hasher.AddData(buffer);
                    blockSigner.AddDocument(hasher.GetHash(), metadata);
                }

                Console.WriteLine("Document count: " + k);
                Console.WriteLine("Tree: " + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
            }
        }

        /// <summary>
        /// Test printing tree with 11 elements
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerPrintTree11Element7MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi);

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"                                                                                                                                                                                          
                                                                                                                                                                                          5R:48092EF  
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                          4L:F7AFBCE                                                                                                                                                                                                  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                               \        
                                          3L:418D6EB                                                                                      3R:318D0F3                                                                                      3R:7C8F6F0  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                  2L:58515B2                                      2R:B0C5D9B                                      2L:B11BCD9                                      2R:A2E9319                                      2L:450CA0B                                                  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \        
      1L:833EDDA                                      1L:DAB08DC              1R:B641272              1L:B162883                                                              1R:CA39D3D              1L:14BF310                                      1R:71974A8  
        /    \                       \                  /    \                  /    \                  /    \                       \                  /                       /    \                  /    \                       \                  /    \        
0L:09A9FE4  0R:M:7E010              0R:BEC84E1  0L:C734EEF  0R:M:7E010  0L:B0CF0A7  0R:M:7E010  0L:BB95E9B  0R:M:7E010              0R:7943B1F  0L:23C4ADE              0L:A360BBA  0R:M:7E010  0L:0347A3E  0R:M:7E010              0R:78C6303  0L:0579A77  0R:M:7E010  
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerPrintTree5Element2MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi);

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"                                                                                          
                                                                                          4R:8CC3714  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                          3L:81C9A75                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                        
                  2L:58515B2                                      2R:BE13727                                                  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \        
      1L:833EDDA                                                                                      1R:B162883  
        /    \                       \                  /                            \                  /    \        
0L:09A9FE4  0R:M:7E010              0R:BEC84E1  0L:C734EEF                          0R:B0CF0A7  0L:BB95E9B  0R:M:7E010  
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerPrintTree5Element3MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi);

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"                                                                                          
                                                                                          4R:8C4C794  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                          3L:D7556F7                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                        
                  2L:D60EFD6                                      2R:B0C5D9B                                                  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                
                              1R:6C55357              1L:DAB08DC              1R:B641272                          
        /                       /    \                  /    \                  /    \           \        
0L:09A9FE4              0L:BEC84E1  0R:M:7E010  0L:C734EEF  0R:M:7E010  0L:B0CF0A7  0R:M:7E010  0R:BB95E9B  
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerPrintTree5ElementWithMetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi);

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"                                                                                          
                                                                                          4R:5FD0F16  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                          3L:3007670                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                        
                  2L:CB29563                                      2R:B0C5D9B                                                  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                       \        
      1L:833EDDA              1R:6C55357              1L:DAB08DC              1R:B641272              1R:B162883  
        /    \                  /    \                  /    \                  /    \                  /    \        
0L:09A9FE4  0R:M:7E010  0L:BEC84E1  0R:M:7E010  0L:C734EEF  0R:M:7E010  0L:B0CF0A7  0R:M:7E010  0L:BB95E9B  0R:M:7E010  
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerPrintTree5ElementNoMetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi);

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
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
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 11 elements with blindign masks
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree11Element8MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"                                                                                                                                                                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                                                                                                                                                                          6R:C58E404  
                                                                                                                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                                                                                                                          5L:C5AFE6D                                                                                                                                                                                                                                                                                                                                                                                                  
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                                                                                                               \        
                                                                                          4L:EA496FB                                                                                                                                                                                      4R:11F98FB                                                                                                                                                                                      4R:BFF7E21  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                          3L:F66D67C                                                                                      3R:29A8004                                                                                      3L:7836708                                                                                      3R:0FDAAC5                                                                                      3L:E73D2C7                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \        
                  2L:A8CE49A                                      2R:C907E14                                      2L:6B7C978                                      2R:173C33F                                      2L:D537A91                                      2R:850A763                                      2L:2EF2402                                      2R:E3080B2                                      2L:1DB30F2                                      2R:C608215                                      2R:CA4EE44  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                              1R:833EDDA                                                                                      1R:DAB08DC                                      1R:B641272                                      1R:B162883                                      1R:5219A57                                                                                                                                      1R:14BF310                                      1R:6FE689E                                      1R:71974A8  
        /                       /    \                  /                            \                  /                       /    \                  /                       /    \                  /                       /    \                  /                       /    \                  /                            \                  /                            \                  /                       /    \                  /                       /    \                  /                       /    \        
0L:4526CE6              0L:09A9FE4  0R:M:7E010  0L:CCBE4C3                          0R:BEC84E1  0L:8E7123B              0L:C734EEF  0R:M:7E010  0L:0518C1E              0L:B0CF0A7  0R:M:7E010  0L:C0249D2              0L:BB95E9B  0R:M:7E010  0L:0341422              0L:7943B1F  0R:M:7E010  0L:139480D                          0R:23C4ADE  0L:892771A                          0R:A360BBA  0L:FDE71A5              0L:0347A3E  0R:M:7E010  0L:748BC6B              0L:78C6303  0R:M:7E010  0L:DA0101F              0L:0579A77  0R:M:7E010  
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5ElementAllMetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"                                                                                                                                                                                          
                                                                                                                                                                                          5R:3D70E30  
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                          4L:274892C                                                                                                                                                                                                  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                        
                                          3L:35136F9                                                                                      3R:DA14B49                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \        
                  2L:A8CE49A                                      2R:8A85301                                      2L:097523F                                      2R:173C33F                                      2R:D537A91  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                              1R:833EDDA                                      1R:6C55357                                      1R:DAB08DC                                      1R:B641272                                      1R:B162883  
        /                       /    \                  /                       /    \                  /                       /    \                  /                       /    \                  /                       /    \        
0L:4526CE6              0L:09A9FE4  0R:M:7E010  0L:CCBE4C3              0L:BEC84E1  0R:M:7E010  0L:E8C8085              0L:C734EEF  0R:M:7E010  0L:0518C1E              0L:B0CF0A7  0R:M:7E010  0L:C0249D2              0L:BB95E9B  0R:M:7E010  
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5ElementNoMetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
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
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5Element3MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metadata);

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"                                                                                                                                                                                          
                                                                                                                                                                                          5R:61E307C  
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                          4L:A69F87C                                                                                                                                                                                                  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                        
                                          3L:F66D67C                                                                                      3R:D2F0485                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \        
                  2L:A8CE49A                                      2R:C907E14                                      2L:8248411                                      2R:55AA865                                      2R:D537A91  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                              1R:833EDDA                                                                                                                                      1R:B641272                                      1R:B162883  
        /                       /    \                  /                            \                  /                            \                  /                       /    \                  /                       /    \        
0L:4526CE6              0L:09A9FE4  0R:M:7E010  0L:CCBE4C3                          0R:BEC84E1  0L:8E7123B                          0R:C734EEF  0L:7637A80              0L:B0CF0A7  0R:M:7E010  0L:C0249D2              0L:BB95E9B  0R:M:7E010  
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Test printing tree with 5 elements with blindign masks
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerWithBlindingMasksPrintTree5Element2MetadataTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Console.WriteLine("Tree: \"" + BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()) + "\"");
            Assert.AreEqual(
                @"                                                                                                                                                                                          
                                                                                                                                                                                          5R:1DD1AB5  
                                                                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                                          4L:70DE5FD                                                                                                                                                                                                  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                                                                        
                                          3L:5A5CCC6                                                                                      3R:DA14B49                                                                                                  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                                      / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \        
                  2L:494220A                                      2R:F42B3E7                                      2L:097523F                                      2R:173C33F                                      2R:97068A3  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                                                              1R:6C55357                                      1R:DAB08DC                                      1R:B641272                                                  
        /                            \                  /                       /    \                  /                       /    \                  /                       /    \                  /                \        
0L:4526CE6                          0R:09A9FE4  0L:18EF136              0L:BEC84E1  0R:M:7E010  0L:E8C8085              0L:C734EEF  0R:M:7E010  0L:0518C1E              0L:B0CF0A7  0R:M:7E010  0L:C0249D2              0R:BB95E9B  
",
                BlockSignerTreeNodeVisualizer.PrintTree(blockSigner.GetRootNode()));
        }

        /// <summary>
        /// Get root node test
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerGetRootNodeTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            blockSigner.AddDocument(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")));
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metadata);
            blockSigner.AddDocument(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")));

            Assert.AreEqual("5R:1DD1AB5A8AB48055A0DBA5EF4209A8A0DA48A4A74CE64AA75929364235517ABC", blockSigner.GetRootNode().ToString(), "Invalid root node");
        }

        /// <summary>
        /// Get root node test when no documents added
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void BlockSignerGetRootNodeNoDocumentsTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, true, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 });

            Assert.AreEqual(null, blockSigner.GetRootNode(), "Invalid root node");
        }
    }
}
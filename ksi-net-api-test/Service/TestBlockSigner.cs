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
using Guardtime.KSI.Signature.MultiSignature;

namespace Guardtime.KSI.Test.Service
{
    public class TestBlockSigner : BlockSigner
    {
        //private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        public TestBlockSigner(Ksi ksi, HashAlgorithm hashAlgorithm = null) : base(ksi, hashAlgorithm)
        {
        }

        public TestBlockSigner(Ksi ksi, bool useBlindingMask, byte[] randomSeed, HashAlgorithm hashAlgorithm = null) : base(ksi, useBlindingMask, randomSeed, hashAlgorithm)
        {
        }

        /// <summary>
        /// Sign given hashes. Returns multi-signature.
        /// </summary>
        public KsiMultiSignature GetMultiSignature()
        {
            if (DocumentNodes.Count == 0)
            {
                return new KsiMultiSignature(new KsiSignatureFactory());
            }

            SignRoot();
            AggregationHashChain existingAggregationHashChain = RootSignature.GetAggregationHashChains()[0];
            return CreateMultiSignature(existingAggregationHashChain);
        }

        /// <summary>
        /// Create multi-signature.
        /// </summary>
        /// <param name="existingAggregationHashChain"></param>
        /// <returns></returns>
        private KsiMultiSignature CreateMultiSignature(AggregationHashChain existingAggregationHashChain)
        {
            //Logger.Debug("Start creating multi-signature.");
            Console.WriteLine("Start creating multi-signature.");

            ulong[] chainIndex = PrepareChainIndex(existingAggregationHashChain);

            KsiMultiSignature multiSignature = new KsiMultiSignature(new KsiSignatureFactory());
            multiSignature.Add(RootSignature);

            foreach (TreeNode node in DocumentNodes)
            {
                AggregationHashChain aggregationHashChain = GetAggregationHashChain(existingAggregationHashChain, node, chainIndex);
                multiSignature.Add(aggregationHashChain);
            }

            //Logger.Debug("End creating multi-signature.");
            Console.WriteLine("End creating multi-signature.");

            return multiSignature;
        }
    }
}
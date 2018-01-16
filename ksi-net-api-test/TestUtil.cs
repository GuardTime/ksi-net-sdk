/*
 * Copyright 2013-2017 Guardtime, Inc.
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
using System.IO;
using System.Reflection;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Test.Signature.Verification;
using Guardtime.KSI.Test.Trust;

namespace Guardtime.KSI.Test
{
    public class TestUtil
    {
        public static T GetCompositeTag<T>(uint type, ITlvTag[] childTags) where T : ITlvTag
        {
            return (T)GetCompositeTag(typeof(T), type, childTags);
        }

        public static ITlvTag GetCompositeTag(Type type, uint tagType, ITlvTag[] childTags)
        {
            RawTag raw;

            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                foreach (ITlvTag tag in childTags)
                {
                    writer.WriteTag(tag);
                }

                raw = new RawTag(tagType, false, false, ((MemoryStream)writer.BaseStream).ToArray());
            }
            object[] args = new object[] { raw };

            ITlvTag value = (ITlvTag)Activator.CreateInstance(type, args);

            // set _value inside CompositeTag
            FieldInfo field = typeof(CompositeTag).GetField("_childTags", BindingFlags.Instance | BindingFlags.NonPublic);

            if (field == null)
            {
                throw new Exception("Cannot find field '_value' inside CompositeTag class.");
            }

            field.SetValue(value, new List<ITlvTag>(childTags));

            return value;
        }

        public static HashAlgorithm GetHashAlgorithm(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return HashAlgorithm.Default;
            }

            HashAlgorithm algorithm = HashAlgorithm.GetByName(name);

            if (algorithm == null)
            {
                throw new Exception("Invalid hmac algorithm name value in config. Name: " + name);
            }

            return algorithm;
        }

        public static KsiSignature GetSignature(string path = null)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, path ?? Resources.KsiSignature_Ok), FileMode.Open))
            {
                return (KsiSignature)new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream);
            }
        }

        public static PublicationsFile GetPublicationsFile(string path = null)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, path ?? Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                return (PublicationsFile)new PublicationsFileFactory(new TestPkiTrustProvider()).Create(stream);
            }
        }

        public static RawTag GetRawTag(string file)
        {
            using (TlvReader reader = new TlvReader(new FileStream(Path.Combine(TestSetup.LocalPath, file), FileMode.Open)))
            {
                return reader.ReadTag();
            }
        }
    }
}
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
using System.IO;
using System.Reflection;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Test
{
    public class TestUtil
    {
        public static T GetCompositeTag<T>(uint type, ITlvTag[] childTags)
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
    }
}
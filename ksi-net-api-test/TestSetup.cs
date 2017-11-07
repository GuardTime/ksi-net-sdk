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
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Threading;
using Guardtime.KSI.Service;
using Guardtime.KSI.Test.Crypto;
using NUnit.Framework;

namespace Guardtime.KSI.Test
{
    [SetUpFixture]
    public class TestSetup
    {
        private static string _localPath;
        private static PduVersion? _pduVersion;

        public static string LocalPath
        {
            get
            {
                if (string.IsNullOrEmpty(_localPath))
                {
                    _localPath = Path.GetDirectoryName(new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath);
                }

                return _localPath;
            }
        }

        public static PduVersion PduVersion
        {
            get
            {
                if (_pduVersion == null)
                {
                    switch (Properties.Settings.Default.PduVersion)
                    {
                        case 1:
                            _pduVersion = PduVersion.v1;
                            break;
                        case 2:
                            _pduVersion = PduVersion.v2;
                            break;
                        default:
                            _pduVersion = PduVersion.v1;
                            break;
                    }
                }
                return _pduVersion.Value;
            }
        }

        [OneTimeSetUp]
        public void RunBeforeAnyTests()
        {
            Thread.CurrentThread.CurrentCulture = new CultureInfo("et-EE");
            KsiProvider.SetCryptoProvider(CryptoTestFactory.CreateProvider());
        }
    }
}
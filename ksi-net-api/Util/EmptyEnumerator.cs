using System;
using System.Collections;

namespace Guardtime.KSI.Util
{
    public class EmptyEnumerator : IEnumerator
    {
        public bool MoveNext()
        {
            return false;
        }

        public void Reset()
        {
        }

        public object Current {
            get
            {
                throw new InvalidOperationException();
            }
        }
    }
}

using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Util
{
    public class EmptyEnumerator<T> : IEnumerator<T>
    {
        public bool MoveNext()
        {
            return false;
        }

        public void Reset()
        {
        }

        T IEnumerator<T>.Current
        {
            get { throw new InvalidOperationException(); }
        }

        public object Current {
            get
            {
                throw new InvalidOperationException();
            }
        }

        public void Dispose()
        {
        }
    }
}

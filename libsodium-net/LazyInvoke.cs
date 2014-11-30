using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sodium
{
    public class LazyInvoke<T>
    {
        private string function, library;
        private T _method;
        private bool missing;

        public LazyInvoke(string function, string library)
        {
            this.function = function;
            this.library = library;
            this.missing = true;
        }

        public T method
        {
            get
            {
                if (missing)
                {
                    _method = DynamicInvoke.GetDynamicInvoke<T>(function, library);
                    missing = false;
                }

                return _method;
            }
        }
    }
}

namespace Sodium
{
  public class LazyInvoke<T>
  {
    private readonly string _function;
    private readonly string _library;
    private T _method;
    private bool _missing;

    public LazyInvoke(string function, string library)
    {
      _function = function;
      _library = library;
      _missing = true;
    }

    public T Method
    {
      get
      {
        if (_missing)
        {
          _method = DynamicInvoke.GetDynamicInvoke<T>(_function, _library);
          _missing = false;
        }

        return _method;
      }
    }
  }
}

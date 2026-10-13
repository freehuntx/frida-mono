// Not referenced by Host: the e2e tests load it on demand (compiled as LazyA.dll and LazyB.dll) to observe assembly loads.
namespace FridaMono.Tests
{
    public static class Lazy
    {
        public static int Value()
        {
            return 7;
        }
    }
}

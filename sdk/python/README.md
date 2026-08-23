# TokenSaver Plugin SDK for Python

This Python 3.10+ standard-library package implements TokenSaver Plugin
Protocol (TSPP) v1 framing, lifecycle handling, validation, exception
isolation, and structured diagnostics. It contains no optimization heuristics.

```python
from tokensaver_plugin import Identity, pass_output, run


def optimize(request):
    return pass_output()


run(Identity("com.example.my-optimizer", "1.0.0"), optimize)
```

Use `optimized(content)` to construct a safe proposal. TokenSaver still
independently verifies UTF-8 safety, output size, and the minimum 20 percent
reduction. Run `python -m unittest discover -s tests -v` before release.

TSPP v1 requires a standalone executable in `plugin.json`. Package Python and
this SDK into that executable with your chosen audited application packager;
do not depend on an ambient interpreter in a distributed plugin.

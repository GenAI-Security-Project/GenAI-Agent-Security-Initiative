# Contributing Guidelines

Pull requests, bug reports, and all other forms of contribution are welcome.

## Code examples

Adding a new code example must be done by opening a pull request.

The example must be added in a subdirectory under `frameworks/SDK` with a consise name where `SDK` is the sdk used to implement the example. If the sdk used is not present please add it in the `framework` folder.

Please ensure that all submissions contain:

1. A `README.md` in the example directory describing:
 * The functionality of the example
 * A writeup of the vulnerability along with references to OWASP Top 10 for LLM
 * Prerequisites to run the code
2. The system itself along with a `Dockerfile` such that it can be run locally.

Consider if the `README.md` should also contain mitigating strategies for the vulnerability.

## Automated verification for zero-dependency `python_stdlib` ASI samples

Samples added under `agentic_top_ten/frameworks/python_stdlib/<sample_name>/` are
checked automatically, both locally and in CI (`.github/workflows/verify-asi-samples.yml`),
by `agentic_top_ten/verify_asi_samples.py`. It discovers every sample directory and
confirms that each one:

* contains `README.md`, `Dockerfile`, and `main.py`;
* has at least one `test_*.py` module; and
* runs `python main.py` and `python -m unittest discover -v` successfully.

Run it yourself from `code_samples/agentic_top_ten/` before opening a pull request:

```bash
python verify_asi_samples.py
```

and run its own test suite with:

```bash
python -m unittest discover -v -p "test_verify_asi_samples.py"
```

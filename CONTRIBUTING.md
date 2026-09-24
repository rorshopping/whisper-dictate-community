# Contributing

Thanks for helping improve Whisper Dictate Community Edition.

## Development setup

Use Python 3.12 on Windows or macOS:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m unittest discover -s tests -p "test_*.py"
```

macOS users should activate the virtual environment with `source .venv/bin/activate` before running the same commands.

The first model download is several gigabytes. Tests use local fixtures and must not download model weights.

## Before opening a pull request

- Keep audio and user data local.
- Do not commit `.env*`, API keys, Stripe values, logs, history, model weights, `.local.txt` files, or generated build output.
- Preserve model license notices and pinned revisions.
- Add or update tests for behavior changes.
- Run the full test suite and `git diff --check`.
- Keep paid-product credentials and release credentials out of this repository.

Model weights are separately licensed. See `MODEL_LICENSES.md` and `THIRD-PARTY-NOTICES.md`.

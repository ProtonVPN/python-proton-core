# ProtonVPN core

The `proton-vpn-core` component contains core logic used by the other ProtonVPN components.

## Development

Even though our CI pipelines always test and build releases using Linux distribution packages,
you can use pip to setup your development environment as follows:

```shell
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Tests

You can run the tests with:

```shell
pytest
```

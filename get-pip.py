"""Install or upgrade pip using Python's bundled, trusted bootstrap."""

import ensurepip


if __name__ == "__main__":
	ensurepip.bootstrap(upgrade=True)

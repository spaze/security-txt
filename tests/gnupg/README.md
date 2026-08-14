This is a GnuPG homedir for the tests that sign or verify, they all get here via the `gnupgHomeDir()` helper.
Files that are not needed for the tests were removed.
And yes, I know this directory contains private keys (and that there's a passphrase in the tests),
but those keys were generated just for the tests and are not used anywhere else.

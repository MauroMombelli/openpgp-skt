# openpgp-skt

This program is used to share PRIVATE key with [OpenKeychain](https://www.openkeychain.org/).

Simply use OpenKeychain to scan the displayed QRcode, and sleect the key to import/export

NOTE: OpenKeychain work in a way that a session can be only Export or Import, while this program allow both Import and Export.
If your keys does not get imported in OpenKeychain, probably is because you have imported a key.
Workaround: Close the session by selecting "done" on OpenKeychain, and then inizialize a new session by scanning again the barcode.

## LICENSE

Right now i'm waiting for an official answer from the original author, https://0xacab.org/dkg/openpgp-skt/issues/3

The idea would be main code in GPL3 and utils in LGPL, and to move those utils library in dedicated repository


# ItsDangerous

* Uses HMAC-SHA1 by default
* Appears to use the message format `<data>.<signature>`.
	* In the case that `URLSafeSerializer` is used, the data is base64 encoded (// TODO: How? Some characters aren't URL safe?)

# Featureset

* Standard serialisation
* URL safe serialisation
* Timed serialisation (both in URL safe and standard forms)

# Signer vs Serializer

* Signer signs arrays of bytes
* Serializer takes objects, converts them into bytes, then runs them through a Signer

# Errors

* Should differentiate between malformed inputs, inputs without matching signatures and expired inputs.

# Format

* Inputs are parsed backwards, using `rsplit` and a customisable separator token.
* Timestamps are base64 encoded bytes, with each byte being concatenated together being the desired output

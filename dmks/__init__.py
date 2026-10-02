"""dead man's kill switch — liveness beacon and sealed-packet release.

If the owner stops checking in from every enrolled device, the switch escalates
ok -> warn -> armed -> release and finally delivers a pre-sealed evidence packet
to pre-enrolled recipients. The server never holds a decryption key.
"""

__version__ = "0.1.0"
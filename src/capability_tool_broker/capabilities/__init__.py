"""Capabilities on top of the macaroon library.

- :mod:`.request`: the canonical broker request and its hash;
- :mod:`.glob`: resource globs with segment-bounded wildcards;
- :mod:`.caveats`: the first-party caveat language (a no-eval predicate DSL);
- :mod:`.keys`: root key ring with key ids for rotation;
- :mod:`.sealed`: X25519 sealed boxes for third-party caveat identifiers;
- :mod:`.thirdparty`: approval caveats issued by the authority and discharged by the approver;
- :mod:`.verifier`: the macaroon verification algorithm (chain, discharges, caveats);
- :mod:`.attenuate`: offline attenuation helpers used for delegation.
"""

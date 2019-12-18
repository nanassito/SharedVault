from crypto import sharing, symetric


def test_scrypt_cfg_serialization():
    orig = symetric.ScryptCfg()
    result = symetric.ScryptCfg.from_json(orig.to_json())
    assert orig == result


def test_no_shares_at_0():
    _secret, shares = sharing.create_shares(3, 5, 23)
    assert 0 not in shares

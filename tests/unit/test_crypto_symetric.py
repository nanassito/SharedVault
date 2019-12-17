from crypto.symetric import ScryptCfg


def test_scrypt_cfg_serialization():
    orig = ScryptCfg()
    result = ScryptCfg.from_json(orig.to_json())
    assert orig == result

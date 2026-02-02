from generate_args import hash_message, split_digest, Address, thash
from hash import poseidon_hash

def test_hash_message():
    randomizer = 0xdeadbeef
    pk_seed = 0xcafebabe
    pk_root = 0xfeedface

    message = [0x11111111, 0x22222222, 0x33333333]
    digest = hash_message(randomizer, pk_seed, pk_root, message)

    assert(digest == 2182198415344895388480530065214389512836123652580788368776596040288394447218)

def test_split_digest():
    """
    fn test_split_xdigest_128s() {
        let digest = 0x5f6f74792de379a6337bbad9e4a1621e38c5e3827d8ae84c41501d68e961;
        let xdigest = split_xdigest_128s(digest);
        assert_eq!(xdigest.leaf_idx, 0x161);
        assert_eq!(xdigest.tree_address, 0xae84c41501d68);
        assert_eq!(words_to_hex(xdigest.mhash), "5f6f74792de379a6337bbad9e4a1621e38c5e3827d");
    }
    """

    digest = 0x5f6f74792de379a6337bbad9e4a1621e38c5e3827d8ae84c41501d68e961
    mhash, tree_addr, leaf_idx = split_digest(digest)
    assert(leaf_idx == 0x161)
    assert(tree_addr == 0xae84c41501d68)
    assert(mhash == 0x5f6f74792de379a6337bbad9e4a1621e38c5e3827d)

def test_initialize_pk():
    pk_seed = 0x1234
    out = poseidon_hash([pk_seed, 0])
    assert(out == 379277542665157213325042857308534457199001041868780771123009522510742340366)

def test_thash():
    pk_seed = 0xdeadbeef
    address = Address()
    address.set_layer(0x01)
    address.set_type(0x02)
    address.set_keypair(0x3456)

    input_data = [0x11111111, 0x22222222, 0x33333333, 0x44444444]
    digest = thash(pk_seed, address, input_data)
    assert(digest == 1190188513163088186241995297500126947589582629387601832785015242379216793975)



if __name__ == "__main__":
    test_hash_message()
    test_split_digest()
    test_initialize_pk()
    test_thash()
    
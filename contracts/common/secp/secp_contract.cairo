%lang starknet
%builtins range_check

from contracts.common.secp.bigint import BigInt3
from contracts.common.secp.secp import verify_ecdsa
from contracts.common.secp.secp_ec import EcPoint

# Verifies a secp256k1 ECDSA signature.
@view
func verify_signature{range_check_ptr}(
        public_key_pt : EcPoint, msg_hash : BigInt3, r : BigInt3, s : BigInt3):
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s)
    return ()
end

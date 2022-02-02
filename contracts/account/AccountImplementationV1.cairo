%lang starknet
# %builtins output pedersen range_check_ptr

from starkware.cairo.common.registers import get_fp_and_pc
from starkware.starknet.common.syscalls import get_contract_address
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.math import unsigned_div_rem, assert_not_zero, assert_nn, assert_nn_le
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.starknet.common.syscalls import call_contract, get_caller_address, get_tx_signature
from starkware.cairo.common.hash_state import (
    hash_init, hash_finalize, hash_update, hash_update_single
)
from starkware.starknet.common.syscalls import delegate_call


###################
# CONSTANTS
###################

# maximum 21 bytes int value
const BYTES21 = 23384026197294446691258957323460528314494920687616


###################
# STRUCTS
###################

struct Message:
    member sender: felt
    member to: felt
    member selector: felt
    member calldata: felt*
    member calldata_size: felt
    member nonce: felt
end


###################
# STORAGE
###################

@storage_var
func current_nonce() -> (res: felt):
end

@storage_var
func default_public_key() -> (res: felt):
end

@storage_var
func public_keys(public_key : felt) -> (res : felt):
end

@storage_var
func owner_count() -> (res: felt):
end

@storage_var
func threshold() -> (res: felt):
end




###################
# GUARDS
###################

@view
func assert_only_self{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }():
    let (self) = get_contract_address()
    let (caller) = get_caller_address()
    assert self = caller
    return ()
end


###################
# CONSTRUCTOR
###################

@constructor
func constructor{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(_public_key: felt):
    default_public_key.write(_public_key)
    public_keys.write(_public_key, 1)
    owner_count.write(1)
    return()
end



###################
# GETTERS
###################

@view
func get_default_public_key{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = default_public_key.read()
    return (res=res)
end

@view
func get_nonce{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = current_nonce.read()
    return (res=res)
end

@view
func is_account{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    return (1)
end



###################
# VIEW FUNCTIONS
###################

@view
func is_valid_signature{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    }(
        hash: felt,
        signature_len: felt,
        signature: felt*
    ) -> ():

    let (_default_public_key) = default_public_key.read()
    let (_owner_count) = owner_count.read()
    let (__fp__, _) = get_fp_and_pc()
    assert_not_zero(signature_len)

    if signature_len == 2:
        assert _owner_count = 1
        signature[2] = _default_public_key

        validate_signatures(hash, signature_len+1, signature)

        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
        tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
    else:
        # assert_nn(signature_len)
        
        let (q,r) = unsigned_div_rem(value=signature_len, div=3)
        assert r = 0
        let (res) = threshold.read()
        assert_nn_le(res, q)
        
        validate_signatures(hash, signature_len, signature)

        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
        tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
    end
    


    return ()
end



###################
# SETTERS
###################

@external
func set_public_keys{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_key: felt):
    assert_only_self()
    public_keys.write(public_key, 1)
    let (_owner_count) = owner_count.read()
    owner_count.write(_owner_count + 1)
    return ()
end

@external
func add_owner{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_key: felt):
    assert_only_self()

    let (authorized_key) = public_keys.read(public_key=public_key)
    assert authorized_key = 0

    public_keys.write(public_key, 1)

    let (_owner_count) = owner_count.read()
    owner_count.write(_owner_count + 1)

    return ()
end



@external
func set_public_key{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_key: felt):
    assert_only_self()
    default_public_key.write(public_key)
    return ()
end


@external
func set_threshold{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(new_threshold: felt):
    assert_only_self()
    threshold.write(new_threshold)
    return ()
end


###################
# EXTERNAL FUNCTIONS
###################

@external
func execute{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr, 
        ecdsa_ptr: SignatureBuiltin*
    }(
        to: felt,
        selector: felt,
        calldata_len: felt,
        calldata: felt*,
        nonce: felt
    ) -> (response_len: felt, response: felt*):
    alloc_locals

    let (__fp__, _) = get_fp_and_pc()
    let (_address) = get_contract_address()
    let (_current_nonce) = current_nonce.read()

    # validate nonce
    assert _current_nonce = nonce

    local message: Message = Message(
        _address,
        to,
        selector,
        calldata,
        calldata_size=calldata_len,
        _current_nonce
    )

    # # validate transaction
    let (hash) = hash_message(&message)
    let (signature_len, signature) = get_tx_signature()

    is_valid_signature(hash, signature_len, signature)

    # bump nonce
    current_nonce.write(_current_nonce + 1)

    # execute call
    let response = call_contract(
        contract_address=message.to,
        function_selector=message.selector,
        calldata_size=message.calldata_size,
        calldata=message.calldata
    )

    return (response_len=response.retdata_size, response=response.retdata)
end



###################
# INTERNAL FUNCTIONS
###################
func validate_signatures{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
    range_check_ptr
}(
    hash: felt,
    signature_len: felt,
    signature: felt*) -> ():

    let (__fp__, _) = get_fp_and_pc()

    if signature_len == 0:
        return ()
    else:
        let sig_r = signature[0]
        let sig_s = signature[1]
        let sig_key = signature[2]
        
        let (authorized_key) = public_keys.read(public_key=sig_key)

        assert authorized_key = 1

        let div_value = sig_key / BYTES21

        if div_value == 0:
            # validate eth signature
            tempvar syscall_ptr: felt* = syscall_ptr
            tempvar range_check_ptr = range_check_ptr
            tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
            tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
        else:
            verify_ecdsa_signature(
                message=hash,
                public_key=sig_key,
                signature_r=sig_r,
                signature_s=sig_s)

            tempvar syscall_ptr: felt* = syscall_ptr
            tempvar range_check_ptr = range_check_ptr
            tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
            tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
        end
        
        return validate_signatures(hash, signature_len - 3, signature + 3)
    end
end  



func default_signature_validation{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    }(
        hash: felt,
        signature_len: felt,
        signature: felt*
    ) -> ():
    let (_public_key) = default_public_key.read()
    
    let div_value = _public_key / BYTES21

    # ethereum signature (smaller than 21 bytes)
    if div_value == 0:
        #verify eth signature
        assert 1 = 0

        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
        tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
    else:
        # SN native signature
        # This interface expects a signature pointer and length to make
        # no assumption about signature validation schemes.
        # But this implementation does, and it expects a (sig_r, sig_s) pair.
        let sig_r = signature[0]
        let sig_s = signature[1]

        verify_ecdsa_signature(
            message=hash,
            public_key=_public_key,
            signature_r=sig_r,
            signature_s=sig_s)
        
        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
        tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
    end

    return ()
end

func hash_message{pedersen_ptr : HashBuiltin*}(message: Message*) -> (res: felt):
    alloc_locals
    # we need to make `res_calldata` local
    # to prevent the reference from being revoked
    let (local res_calldata) = hash_calldata(message.calldata, message.calldata_size)
    let hash_ptr = pedersen_ptr
    with hash_ptr:
        let (hash_state_ptr) = hash_init()
        # first three iterations are 'sender', 'to', and 'selector'
        let (hash_state_ptr) = hash_update(
            hash_state_ptr, 
            message, 
            3
        )
        let (hash_state_ptr) = hash_update_single(
            hash_state_ptr, res_calldata)
        let (hash_state_ptr) = hash_update_single(
            hash_state_ptr, message.nonce)
        let (res) = hash_finalize(hash_state_ptr)
        let pedersen_ptr = hash_ptr
        return (res=res)
    end
end

func hash_calldata{pedersen_ptr: HashBuiltin*}(
        calldata: felt*,
        calldata_size: felt
    ) -> (res: felt):
    let hash_ptr = pedersen_ptr
    with hash_ptr:
        let (hash_state_ptr) = hash_init()
        let (hash_state_ptr) = hash_update(
            hash_state_ptr,
            calldata,
            calldata_size
        )
        let (res) = hash_finalize(hash_state_ptr)
        let pedersen_ptr = hash_ptr
        return (res=res)
    end
end

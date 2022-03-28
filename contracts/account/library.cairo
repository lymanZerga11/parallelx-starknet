
%lang starknet

from starkware.cairo.common.registers import get_fp_and_pc
from starkware.starknet.common.syscalls import get_contract_address
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.math import unsigned_div_rem, assert_not_zero, assert_nn, assert_nn_le, assert_in_range, assert_not_equal
from starkware.starknet.common.syscalls import call_contract, get_caller_address, get_tx_info
from starkware.cairo.common.hash_state import (
    hash_init, hash_finalize, hash_update, hash_update_single
)

from contracts.common.interface.ERC165 import (
    ERC165_supports_interface, 
    ERC165_register_interface
)

from contracts.common.utils.constants import PREFIX_TRANSACTION 



###################
# CONSTANTS
###################

const VERSION = '0.1.0'
# const BYTES21 = 23384026197294446691258957323460528314494920687616




###################
# STORAGE
###################

@storage_var
func Account_current_nonce() -> (res: felt):
end

@storage_var
func Account_public_keys(public_key : felt) -> (res : felt):
end

@storage_var
func Account_public_key_list(index : felt) -> (public_key : felt):
end

# current owner count
@storage_var
func Account_public_key_count() -> (res: felt):
end

# a counter that gives a uniqe index to newly added public keys
@storage_var
func Account_public_key_last_index() -> (res: felt):
end

# multi-sig approval threshold 
@storage_var
func Account_threshold() -> (res: felt):
end

# default public key is used when the the wallet is controlled by one public key
@storage_var
func Account_default_public_key() -> (res: felt):
end





###################
# GETTERS
###################


func Account_get_nonce{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account_current_nonce.read()
    return (res=res)
end

func Account_get_default_public_key{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account_default_public_key.read()
    return (res=res)
end

func Account_get_public_key_at_index{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(index: felt) -> (res: felt):
    let (res) = Account_public_key_list.read(index)
    return (res=res)
end

func Account_get_public_key_index{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_key: felt) -> (res: felt):
    let (res) = Account_public_keys.read(public_key)
    return (res=res)
end

func Account_get_public_key_count{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account_public_key_count.read()
    return (res=res)
end

func Account_get_public_key_last_index{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account_public_key_last_index.read()
    return (res=res)
end

func Account_get_threshold{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account_threshold.read()
    return (res=res)
end




###################
# SETTERS
###################


func Account_add_public_key{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_key: felt, new_threshold: felt) -> ():
    
    let (index) = Account_public_keys.read(public_key)
    assert index = 0

    let (count) = Account_public_key_count.read()
    tempvar new_count = count + 1

    
    let (last_index) = Account_get_public_key_last_index()
    tempvar new_last_index = last_index + 1

    Account_public_keys.write(public_key, new_last_index)
    Account_public_key_list.write(new_last_index, public_key)
    Account_public_key_count.write(new_count)
    Account_public_key_last_index.write(new_last_index)

    if new_threshold != 0:
        Account_change_threshold(new_threshold)
    end

    return ()
end

func Account_change_default_public_key{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_key: felt) -> ():
    
    let (index) = Account_public_keys.read(public_key)
    assert_not_zero(index)

    Account_default_public_key.write(public_key)

    return ()
end

# add multiple public keys in one call
func Account_add_public_keys{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_keys_len: felt, public_keys: felt*, new_threshold: felt) -> ():
    
    if public_keys_len == 0:
        return ()
    end

    if public_keys_len == 1:
        Account_add_public_key(public_keys[public_keys_len - 1], new_threshold)
    else:
        Account_add_public_key(public_keys[public_keys_len - 1], 0)
    end


    return Account_add_public_keys(public_keys_len - 1, public_keys, new_threshold)
end

# 
func Account_remove_public_key{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_key: felt, new_threshold: felt, new_default_public_key: felt) -> ():
    let (__fp__, _) = get_fp_and_pc()


    
    let (default_public_key) = Account_get_default_public_key()

    if default_public_key == public_key:
        assert_not_equal(new_default_public_key, default_public_key)

        Account_change_default_public_key(new_default_public_key)

        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    else:
        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    end
        

    let (threshold) = Account_get_threshold()
    let (count) = Account_public_key_count.read()
    tempvar new_count = count - 1

    assert_not_zero(new_count)

    let (index) = Account_get_public_key_index(public_key)
    assert_not_zero(index)

    Account_public_keys.write(public_key, 0)
    Account_public_key_list.write(index, 0)
    Account_public_key_count.write(new_count)

    if new_threshold == 0:
        assert_nn_le(threshold, new_count)
        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
        
    else:
        Account_change_threshold(new_threshold)

        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
        tempvar range_check_ptr = range_check_ptr
    end

    return ()
end



func Account_change_threshold{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(new_threshold: felt) -> ():

    let (count) = Account_public_key_count.read()
    assert_in_range(new_threshold, 1, count + 1)

    Account_threshold.write(new_threshold)

    return ()
end





# ###################
# # INTERNAL FUNCTIONS
# ###################

func Account_initializer{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_keys_len: felt, public_keys: felt*, threshold: felt):
    Account_add_public_keys(public_keys_len, public_keys, threshold)

    # sets the default key to the first key in the array
    Account_change_default_public_key(public_keys[0])

    # Account magic value derived from ERC165 calculation of IAccount
    ERC165_register_interface(0xf10dbd44)
    return()
end



###################
# VIEW FUNCTIONS
###################


func Account_is_valid_signature{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr, 
        ecdsa_ptr: SignatureBuiltin*
    }(
        hash: felt,
        signature_len: felt,
        signature: felt*
    ) -> ():
    alloc_locals
    let (_owner_count) = Account_get_public_key_count()
    let (_threshold) = Account_get_threshold()

    let (__fp__, _) = get_fp_and_pc()
    assert_not_zero(signature_len)

    # when the wallet has only one owner (This makes the implementation compatible with OpenZeppelin and Argent)
    if signature_len == 2:
        assert _threshold = 1

        let (_default_public_key) = Account_get_default_public_key()

        let (local extended_sig) = alloc()
        
        assert[extended_sig] = signature[0]
        assert[extended_sig + 1] = signature[1]
        assert[extended_sig + 2] = _default_public_key

        validate_signatures(hash, signature_len+1, extended_sig, 1)

        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
        tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
    else:
        assert_nn(signature_len)
        
        # verifies that each signature is provided in the format [r, s, public_key]
        let (q,r) = unsigned_div_rem(value=signature_len, div=3)
        assert r = 0

        # check if the wallet threshold is less or equal to the number of the provided signatures
        let (res) = Account_get_threshold()
        assert_nn_le(res, q)
        
        validate_signatures(hash, signature_len, signature, _threshold)

        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
        tempvar ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
    end
    

    return ()

end

func validate_signatures{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
    range_check_ptr
}(
    hash: felt,
    signature_len: felt,
    signature: felt*,
    threshold: felt) -> ():

    let (__fp__, _) = get_fp_and_pc()

    if signature_len == 0:
        assert threshold = 0
        return ()
    else:
        if threshold == 0:
            return ()
        end
        
        let sig_r = signature[0]
        let sig_s = signature[1]
        let sig_key = signature[2]
        
        let (authorized_key) = Account_get_public_key_index(sig_key)

        assert_not_zero(authorized_key)

        #TODO
        # validate eth signatures


        verify_ecdsa_signature(
            message=hash,
            public_key=sig_key,
            signature_r=sig_r,
            signature_s=sig_s)

        
        return validate_signatures(hash, signature_len - 3, signature + 3, threshold - 1)
    end
end









## IMPORTED FROM OPENZEPPELIN SINCE CAIRO DOESN'T SUPPORT INDIVIDUAL IMPORTS
## WITHOUT CHECKING FOR OVERRIDES ON THE UNIMPORTED FUNCTIONS/STRUCTS

#
# Structs
#

struct MultiCall:
    member account: felt
    member calls_len: felt
    member calls: Call*
    member nonce: felt
    member max_fee: felt
    member version: felt
end

struct Call:
    member to: felt
    member selector: felt
    member calldata_len: felt
    member calldata: felt*
end

# Tmp struct introduced while we wait for Cairo
# to support passing `[AccountCall]` to __execute__
struct AccountCallArray:
    member to: felt
    member selector: felt
    member data_offset: felt
    member data_len: felt
end


#
# Guards
#

func Account_assert_only_self{syscall_ptr : felt*}():
    let (self) = get_contract_address()
    let (caller) = get_caller_address()
    with_attr error_message("Account: caller is not this account"):
        assert self = caller
    end
    return ()
end



func Account_execute{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr, 
        ecdsa_ptr: SignatureBuiltin*
    }(
        call_array_len: felt,
        call_array: AccountCallArray*,
        calldata_len: felt,
        calldata: felt*,
        nonce: felt
    ) -> (response_len: felt, response: felt*):
    alloc_locals

    let (__fp__, _) = get_fp_and_pc()
    let (tx_info) = get_tx_info()
    let (_current_nonce) = Account_current_nonce.read()

    # validate nonce
    assert _current_nonce = nonce

    # TMP: Convert `AccountCallArray` to 'Call'.
    let (calls : Call*) = alloc()
    from_call_array_to_call(call_array_len, call_array, calldata, calls)
    let calls_len = call_array_len

    local multicall: MultiCall = MultiCall(
        tx_info.account_contract_address,
        calls_len,
        calls,
        _current_nonce,
        tx_info.max_fee,
        tx_info.version
    )

    # validate transaction
    let (hash) = hash_multicall(&multicall)
    Account_is_valid_signature(hash, tx_info.signature_len, tx_info.signature)

    # bump nonce
    Account_current_nonce.write(_current_nonce + 1)

    # execute call
    let (response : felt*) = alloc()
    let (response_len) = execute_list(multicall.calls_len, multicall.calls, response)

    return (response_len=response_len, response=response)
end

func execute_list{syscall_ptr: felt*}(
        calls_len: felt,
        calls: Call*,
        response: felt*
    ) -> (response_len: felt):
    alloc_locals

    # if no more calls
    if calls_len == 0:
       return (0)
    end
    
    # do the current call
    let this_call: Call = [calls]
    let res = call_contract(
        contract_address=this_call.to,
        function_selector=this_call.selector,
        calldata_size=this_call.calldata_len,
        calldata=this_call.calldata
    )
    # copy the result in response
    memcpy(response, res.retdata, res.retdata_size)
    # do the next calls recursively
    let (response_len) = execute_list(calls_len - 1, calls + Call.SIZE, response + res.retdata_size)
    return (response_len + res.retdata_size)
end

func hash_multicall{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*
    } (
        multicall: MultiCall*
    ) -> (res: felt):
    alloc_locals
    let (calls_hash) = hash_call_array(multicall.calls_len, multicall.calls)
    let hash_ptr = pedersen_ptr
    with hash_ptr:
        let (hash_state_ptr) = hash_init()
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, PREFIX_TRANSACTION)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, multicall.account)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, calls_hash)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, multicall.nonce)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, multicall.max_fee)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, multicall.version)
        let (res) = hash_finalize(hash_state_ptr)
        let pedersen_ptr = hash_ptr
        return (res=res)
    end
end

func hash_call_array{pedersen_ptr: HashBuiltin*}(
        calls_len: felt,
        calls: Call*
    ) -> (res: felt):
    alloc_locals

    # convert [call] to [Hash(call)]
    let (hash_array : felt*) = alloc()
    hash_call_loop(calls_len, calls, hash_array)

    # hash [Hash(call)]
    let hash_ptr = pedersen_ptr
    with hash_ptr:
        let (hash_state_ptr) = hash_init()
        let (hash_state_ptr) = hash_update(hash_state_ptr, hash_array, calls_len)
        let (res) = hash_finalize(hash_state_ptr)
        let pedersen_ptr = hash_ptr
        return (res=res)
    end
end

func hash_call_loop{pedersen_ptr: HashBuiltin*}(
        calls_len: felt,
        calls: Call*,
        hash_array: felt*
    ):
    if calls_len == 0:
        return ()
    end
    let this_call = [calls]
    let (calldata_hash) = hash_calldata(this_call.calldata_len, this_call.calldata)
    let hash_ptr = pedersen_ptr
    with hash_ptr:
        let (hash_state_ptr) = hash_init()
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, this_call.to)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, this_call.selector)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, calldata_hash)
        let (res) = hash_finalize(hash_state_ptr)
        let pedersen_ptr = hash_ptr
        assert [hash_array] = res
    end
    hash_call_loop(calls_len - 1, calls + Call.SIZE, hash_array + 1)
    return()
end

func hash_calldata{pedersen_ptr: HashBuiltin*}(
        calldata_len: felt,
        calldata: felt*
    ) -> (res: felt):
    let hash_ptr = pedersen_ptr
    with hash_ptr:
        let (hash_state_ptr) = hash_init()
        let (hash_state_ptr) = hash_update(
            hash_state_ptr,
            calldata,
            calldata_len
        )
        let (res) = hash_finalize(hash_state_ptr)
        let pedersen_ptr = hash_ptr
        return (res=res)
    end
end

func from_call_array_to_call{syscall_ptr: felt*}(
        call_array_len: felt,
        call_array: AccountCallArray*,
        calldata: felt*,
        calls: Call*
    ):
    # if no more calls
    if call_array_len == 0:
       return ()
    end
    
    # parse the current call
    assert [calls] = Call(
            to=[call_array].to,
            selector=[call_array].selector,
            calldata_len=[call_array].data_len,
            calldata=calldata + [call_array].data_offset
        )
    
    # parse the remaining calls recursively
    from_call_array_to_call(call_array_len - 1, call_array + AccountCallArray.SIZE, calldata, calls + Call.SIZE)
    return ()
end

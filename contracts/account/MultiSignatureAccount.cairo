# SPDX-License-Identifier: MIT
# Multi-Signature Wallet Implementation by Parallel Finance

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.starknet.common.syscalls import call_contract, get_caller_address, get_tx_info

from contracts.account.library import (
    AccountCallArray,
    Account_execute,
    Account_assert_only_self,
    Account_get_nonce,
    Account_get_public_key_at_index,
    Account_get_public_key_index,
    Account_get_public_key_count,
    Account_get_public_key_last_index,
    Account_get_threshold,
    Account_initializer,
    Account_add_public_keys,
    Account_add_public_key,
    Account_remove_public_key,
    Account_change_threshold,
    Account_change_default_public_key,
    Account_get_default_public_key,
    Account_is_valid_signature
)

from contracts.common.interface.ERC165 import ERC165_supports_interface 

###################
# GETTERS
###################

@view
func get_public_key{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account_get_default_public_key()
    return (res=res)
end

@view
func get_public_key_at_index{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(index: felt) -> (res: felt):
    let (res) = Account_get_public_key_at_index(index)
    return (res=res)
end

@view
func get_public_key_index{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_key: felt) -> (res: felt):
    let (res) = Account_get_public_key_index(public_key)
    return (res=res)
end

@view
func get_public_key_count{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account_get_public_key_count()
    return (res=res)
end

@view
func get_threshold{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account_get_threshold()
    return (res=res)
end

@view
func get_nonce{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account_get_nonce()
    return (res=res)
end

@view
func supportsInterface{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (interfaceId: felt) -> (success: felt):
    let (success) = ERC165_supports_interface(interfaceId)
    return (success)
end

###################
# SETTERS
###################

@external
func add_public_keys{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_keys_len: felt, public_keys: felt*, new_threshold: felt):
    Account_assert_only_self()

    Account_add_public_keys(public_keys_len, public_keys, new_threshold)
    return ()
end


@external
func add_public_key{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_key: felt, new_threshold: felt):
    Account_assert_only_self()

    Account_add_public_key(public_key, new_threshold)
    return ()
end


@external
func remove_public_key{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_key: felt, new_threshold: felt, new_default_public_key: felt):
    Account_assert_only_self()

    Account_remove_public_key(public_key, new_threshold, new_default_public_key)
    return ()
end

@external
func change_threshold{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(new_threshold: felt):
    Account_assert_only_self()

    Account_change_threshold(new_threshold)
    return ()
end


@external
func change_default_public_key{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(new_default_public_key: felt):
    Account_assert_only_self()

    Account_change_default_public_key(new_default_public_key)
    return ()
end


###################
# INITIALIZER
###################

@constructor
func constructor{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_keys_len: felt, public_keys: felt*, threshold: felt):

    Account_initializer(public_keys_len, public_keys, threshold)
    return ()
end


###################
# VIEW FUNCTIONS
###################

@view
func is_valid_signature{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr, 
        ecdsa_ptr: SignatureBuiltin*
    }(
        hash: felt,
        signature_len: felt,
        signature: felt*
    ) -> ():

    Account_is_valid_signature(hash, signature_len, signature)
    return ()
end



###################
# EXTERNAL FUNCTIONS
###################

# TODO change this to __execute__ and update the compile/deploy/tests scripts
@external
func execute{ 
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

    let (response_len, response) = Account_execute(
        call_array_len,
        call_array,
        calldata_len,
        calldata,
        nonce
    )
    return (response_len=response_len, response=response)
end
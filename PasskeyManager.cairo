// SPDX-License-Identifier: MIT
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_not_zero
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.memcpy import memcpy

// Structs
struct Passkey:
    member public_key : felt
    member last_used_nonce : felt
    member is_active : felt
end

// Storage variables
@storage_var
func user_passkeys(user : felt) -> (passkey : Passkey):
end

@storage_var
func used_challenges(challenge : felt) -> (used : felt):
end

// Events
@event
func passkey_registered(user : felt, public_key : felt):
end

@event
func authentication_challenge(user : felt, challenge : felt):
end

@event
func authentication_successful(user : felt):
end

// Constructor
@constructor
func constructor{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}():
    return ()
end

// Register a new passkey for the user
@external
func register_passkey{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(public_key : felt):
    let (user) = get_caller_address()
    
    // Check if passkey is already registered
    let (existing_passkey) = user_passkeys.read(user)
    assert existing_passkey.is_active = 0

    // Create and store new passkey
    let new_passkey = Passkey(
        public_key=public_key, 
        last_used_nonce=0, 
        is_active=1
    )
    user_passkeys.write(user, new_passkey)

    // Emit registration event
    passkey_registered.emit(user, public_key)
    return ()
end

// Generate authentication challenge
@external
func generate_auth_challenge{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}() -> (challenge : felt):
    let (user) = get_caller_address()
    
    // Retrieve user's passkey
    let (passkey) = user_passkeys.read(user)
    assert passkey.is_active = 1

    // Generate challenge using hash of user address, block timestamp, and nonce
    let (challenge) = hash2{hash_ptr=pedersen_ptr}(user, passkey.last_used_nonce)

    // Emit challenge event
    authentication_challenge.emit(user, challenge)
    
    return (challenge)
end

// Verify authentication
@external
func verify_authentication{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    signature_ptr : SignatureBuiltin*,
    range_check_ptr
}(challenge : felt, r : felt, s : felt):
    let (user) = get_caller_address()
    
    // Check if passkey is registered
    let (passkey) = user_passkeys.read(user)
    assert passkey.is_active = 1

    // Check if challenge has been used
    let (is_challenge_used) = used_challenges.read(challenge)
    assert is_challenge_used = 0

    // Verify signature
    verify_ecdsa_signature(
        message=challenge,
        public_key=passkey.public_key, 
        signature_r=r,
        signature_s=s
    )

    // Mark challenge as used
    used_challenges.write(challenge, 1)

    // Increment nonce
    let updated_passkey = Passkey(
        public_key=passkey.public_key,
        last_used_nonce=passkey.last_used_nonce + 1,
        is_active=1
    )
    user_passkeys.write(user, updated_passkey)

    // Emit successful authentication event
    authentication_successful.emit(user)
    return ()
end

// View function to check if a user has an active passkey
@view
func is_passkey_active{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
}(user : felt) -> (active : felt):
    let (passkey) = user_passkeys.read(user)
    return (passkey.is_active)
end

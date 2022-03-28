# ParallelX (Crypto Bank)

This is the Cairo implementaion of ParallelX. A platform that enables user groups to govern crypto asset account actions through an authorization configuration capable of providing granular level control over specific account actions.

This implementation is considered a superset of OpenZeppelin standard Starknet account implementation. 


## Current Supported Actions

* Create a new signle owner account with 1 public key (behavior is identical to OpenZeppelin's)
* Transfer ownership of a single owner account
* Create new multi-sig account with n public keys (owners)
* Add new public key to the account
* Remove a public key from the account
* Change account approval threshold


## To be implemented

* Social recovery mechanism
* Spending rules
* Executing transactions through approved modules
* Utility modules:
    * Bulk payment modules
    * Stream payment modules
    * DEFI integaration modules



## Requirements

* Node.js v12.22.4+
* npm/npx v7.21.1+
* Docker v20.10.8+

This package uses [Hardhat Starknet Plugin](https://github.com/Shard-Labs/starknet-hardhat-plugin) for compiling, deploying and testing Cairo contracts. 

If you wish to deploy and test the contracts locally then consider using [Starknet DevNet](https://github.com/Shard-Labs/starknet-devnet)


### Defaults

Connected to `starknet-devnet` expected to be available on `http://localhost:5000` by default. 
To use a different network update the `hardhat.config.ts` file. 


# Getting Started
## Scripts
`npm build` - Compile all contracts 
`npm test` - Run contract tests against the configured environment


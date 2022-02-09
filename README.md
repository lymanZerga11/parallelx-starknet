# ParallelX (Crypto Bank)

This is the Cairo implementaion of ParallelX. A platform that enables user groups to govern crypto asset account actions through an authorization configuration capable of providing granular level control over specific account actions.


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


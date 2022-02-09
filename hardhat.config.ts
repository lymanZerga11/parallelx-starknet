import * as dotenv from "dotenv";
import { HardhatUserConfig, task } from "hardhat/config";
import "@nomiclabs/hardhat-waffle";
import "@shardlabs/starknet-hardhat-plugin";

dotenv.config();
const config: HardhatUserConfig = {
  cairo: {
    version: "0.7.0"
  },
  networks: {
    devnet: {
      url: "http://localhost:5000"
    }
  },
  mocha: {
    // Used for deployment in Mocha tests
    // Defaults to "alpha" (for Alpha testnet), which is preconfigured even if you don't see it under `networks:`
    starknetNetwork: "devnet"
  }
};

export default config;

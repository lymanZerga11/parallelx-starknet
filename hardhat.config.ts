import * as dotenv from "dotenv";
import { HardhatUserConfig, task } from "hardhat/config";
import "@nomiclabs/hardhat-waffle";
import "@shardlabs/starknet-hardhat-plugin";

dotenv.config();


const config: HardhatUserConfig = {
  starknet: {
    // The default in this version of the plugin
    dockerizedVersion: "0.8.0",
    network: "devnet",
    wallets: {
      MyWallet: {
        accountName: "OpenZeppelin",
        modulePath: "./contracts.account.MultiSignatureAccount",
        accountPath: "~/.starknet_accounts"
      }
    }
  },
  networks: {
    devnet: {
      url: "http://localhost:5000"
    }
  }
};

export default config;

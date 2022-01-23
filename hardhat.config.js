require("dotenv").config();
require("@nomiclabs/hardhat-waffle");
// starknet custom plugin
require("@shardlabs/starknet-hardhat-plugin");

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  cairo: {
    version: "0.7.0"
  },
  networks: {
    devnet: {
      url: "http://localhost:5000"
    }
  }
};

require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();
const networks = { localhost: {
    url: "http://127.0.0.1:8545",
    chainId: 31337,
  },};
if (process.env.SEPOLIA_RPC_URL && process.env.DEPLOYER_KEY) networks.sepolia = { url: process.env.SEPOLIA_RPC_URL, accounts: [process.env.DEPLOYER_KEY] };
module.exports = { solidity: { version: "0.8.24", settings: { optimizer: { enabled: true, runs: 200 } } }, networks };

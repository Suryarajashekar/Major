const fs = require("fs");
async function main() {
  const c = await (await ethers.getContractFactory("AIMarketplace")).deploy();
  await c.waitForDeployment();
  const address = await c.getAddress();
  const abi = JSON.parse(fs.readFileSync("artifacts/contracts/AIMarketplace.sol/AIMarketplace.json")).abi;
  const out = JSON.stringify({ address, abi }, null, 2);
  fs.writeFileSync("backend/contract.json", out);
  fs.writeFileSync("frontend/src/contract.json", out);
  console.log("AIMarketplace deployed to", address);
}
main().catch((e) => { console.error(e); process.exit(1); });

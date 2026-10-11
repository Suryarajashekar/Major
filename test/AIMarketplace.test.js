const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AIMarketplace", () => {
  let m, owner, creator, buyer, hash;
  const price = ethers.parseEther("1");
  beforeEach(async () => {
    [owner, creator, buyer] = await ethers.getSigners();
    m = await (await ethers.getContractFactory("AIMarketplace")).deploy();
    hash = ethers.id("weights");
    await m.connect(creator).listModel("Sentiment-v1", "ipfs://cid", hash, price);
  });
  it("lists a model and licenses the creator", async () => {
    expect(await m.modelCount()).to.equal(1);
    expect(await m.hasLicense(0, creator.address)).to.equal(true);
  });
  it("rejects oversized metadata and invalid model ids", async () => {
    await expect(m.connect(creator).listModel("x", "a".repeat(2049), hash, price))
      .to.be.revertedWithCustomError(m, "BadInput");
    await expect(m.getModel(99)).to.be.revertedWithCustomError(m, "ModelNotFound");
  });
  it("splits payment between creator and platform", async () => {
    await m.connect(buyer).buyLicense(0, { value: price });
    expect(await m.hasLicense(0, buyer.address)).to.equal(true);
    expect(await m.earnings(creator.address)).to.equal((price * 9750n) / 10000n);
    expect(await m.platformEarnings()).to.equal((price * 250n) / 10000n);
  });
  it("rejects wrong payment and double purchase", async () => {
    await expect(m.connect(buyer).buyLicense(0, { value: 1 })).to.be.revertedWithCustomError(m, "WrongPayment");
    await m.connect(buyer).buyLicense(0, { value: price });
    await expect(m.connect(buyer).buyLicense(0, { value: price })).to.be.revertedWithCustomError(m, "AlreadyLicensed");
  });
  it("only licensed users rate, once", async () => {
    await expect(m.connect(buyer).rate(0, 5)).to.be.revertedWithCustomError(m, "NotLicensed");
    await m.connect(buyer).buyLicense(0, { value: price });
    await m.connect(buyer).rate(0, 4);
    await expect(m.connect(buyer).rate(0, 5)).to.be.reverted;
    expect((await m.getModel(0)).ratingSum).to.equal(4);
  });
  it("lets creator withdraw", async () => {
    await m.connect(buyer).buyLicense(0, { value: price });
    await expect(m.connect(creator).withdraw()).to.changeEtherBalance(creator, (price * 9750n) / 10000n);
  });
  it("emits fee and platform withdrawal events", async () => {
    await expect(m.setFee(500)).to.emit(m, "FeeUpdated").withArgs(250, 500);
    await m.connect(buyer).buyLicense(0, { value: price });
    await expect(m.withdrawPlatform()).to.emit(m, "PlatformWithdrawn").withArgs(owner.address, (price * 500n) / 10000n);
  });
  it("pauses purchases but not withdrawals", async () => {
    await m.connect(buyer).buyLicense(0, { value: price });
    await m.pause();
    await expect(m.connect(buyer).rate(0, 5)).to.not.be.reverted;
    await expect(m.listModel("x", "ipfs://y", hash, 1)).to.be.reverted;
    await expect(m.connect(creator).withdraw()).to.not.be.reverted;
  });
  it("uses two-step ownership and blocks renounce", async () => {
    await expect(m.renounceOwnership()).to.be.reverted;
    await m.transferOwnership(buyer.address);
    expect(await m.owner()).to.not.equal(buyer.address);
    await m.connect(buyer).acceptOwnership();
    expect(await m.owner()).to.equal(buyer.address);
  });
});

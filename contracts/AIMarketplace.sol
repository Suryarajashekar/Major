// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/// @title NeuralBazaar: a decentralised marketplace for AI model licenses
/// @notice Creators list models (metadata + content hash on IPFS/off-chain), buyers pay once for a
///         license, and the off-chain gateway checks `hasLicense` before serving inference.
contract AIMarketplace is ReentrancyGuard, Ownable2Step, Pausable {
    struct Model {
        address creator;
        string name;
        string metadataURI;   // ipfs://... describing the model, API schema, docs
        bytes32 contentHash;  // sha256 of the model artifact, proves integrity
        uint256 price;        // wei per license
        bool active;
        uint32 sales;
        uint32 ratingSum;
        uint32 ratingCount;
    }

    Model[] private models;
    mapping(uint256 => mapping(address => bool)) public hasLicense;
    mapping(uint256 => mapping(address => bool)) public hasRated;
    mapping(address => uint256) public earnings;

    uint256 public feeBps = 250; // 2.5% platform fee
    uint256 public constant MAX_FEE_BPS = 1000;
    uint256 public constant MAX_METADATA_URI_LENGTH = 2048;
    uint256 public platformEarnings;

    event ModelListed(uint256 indexed id, address indexed creator, string name, uint256 price);
    event ModelUpdated(uint256 indexed id, uint256 price, bool active);
    event LicensePurchased(uint256 indexed id, address indexed buyer, uint256 price);
    event ModelRated(uint256 indexed id, address indexed rater, uint8 score);
    event Withdrawn(address indexed to, uint256 amount);
    event PlatformWithdrawn(address indexed to, uint256 amount);
    event FeeUpdated(uint256 previousFeeBps, uint256 newFeeBps);

    error NotCreator();
    error Inactive();
    error WrongPayment();
    error AlreadyLicensed();
    error NotLicensed();
    error BadInput();
    error NothingToWithdraw();
    error ModelNotFound();

    constructor() Ownable(msg.sender) {}

    function listModel(string calldata name, string calldata metadataURI, bytes32 contentHash, uint256 price)
        external whenNotPaused returns (uint256 id)
    {
        if (
            contentHash == bytes32(0) ||
            bytes(name).length == 0 ||
            bytes(name).length > 80 ||
            bytes(metadataURI).length == 0 ||
            bytes(metadataURI).length > MAX_METADATA_URI_LENGTH
        ) revert BadInput();
        id = models.length;
        models.push(Model(msg.sender, name, metadataURI, contentHash, price, true, 0, 0, 0));
        hasLicense[id][msg.sender] = true; // creators can always use their own model
        emit ModelListed(id, msg.sender, name, price);
    }

    function updateModel(uint256 id, uint256 price, bool active) external {
        Model storage m = _model(id);
        if (m.creator != msg.sender) revert NotCreator();
        m.price = price;
        m.active = active;
        emit ModelUpdated(id, price, active);
    }

    function buyLicense(uint256 id) external payable nonReentrant whenNotPaused {
        Model storage m = _model(id);
        if (!m.active) revert Inactive();
        if (hasLicense[id][msg.sender]) revert AlreadyLicensed();
        if (msg.value != m.price) revert WrongPayment();
        hasLicense[id][msg.sender] = true;
        m.sales++;
        uint256 fee = (msg.value * feeBps) / 10_000;
        platformEarnings += fee;
        earnings[m.creator] += msg.value - fee;
        emit LicensePurchased(id, msg.sender, msg.value);
    }

    function rate(uint256 id, uint8 score) external {
        Model storage m = _model(id);
        if (score < 1 || score > 5) revert BadInput();
        if (!hasLicense[id][msg.sender] || m.creator == msg.sender) revert NotLicensed();
        if (hasRated[id][msg.sender]) revert BadInput();
        hasRated[id][msg.sender] = true;
        models[id].ratingSum += score;
        models[id].ratingCount++;
        emit ModelRated(id, msg.sender, score);
    }

    /// @dev pull-payment pattern: creators withdraw their own earnings
    function withdraw() external nonReentrant {
        uint256 amount = earnings[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        earnings[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function withdrawPlatform() external onlyOwner nonReentrant {
        uint256 amount = platformEarnings;
        if (amount == 0) revert NothingToWithdraw();
        platformEarnings = 0;
        (bool ok, ) = payable(owner()).call{value: amount}("");
        require(ok, "transfer failed");
        emit PlatformWithdrawn(owner(), amount);
    }

    function setFee(uint256 bps) external onlyOwner {
        if (bps > MAX_FEE_BPS) revert BadInput();
        uint256 previous = feeBps;
        feeBps = bps;
        emit FeeUpdated(previous, bps);
    }

    /// @notice emergency stop for listing and purchases; withdrawals stay open so funds are never trapped
    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
    /// @dev disabled: a marketplace without an owner could never pause or change fees
    function renounceOwnership() public pure override { revert BadInput(); }

    function modelCount() external view returns (uint256) { return models.length; }
    function getModel(uint256 id) external view returns (Model memory) { return _model(id); }

    function _model(uint256 id) internal view returns (Model storage model) {
        if (id >= models.length) revert ModelNotFound();
        model = models[id];
    }
}

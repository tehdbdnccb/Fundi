// contracts/Attestation.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FundiAttestation
/// @notice Soulbound (non-transferable) attestation of a safety event or training
///         completion. Deliberately minimal on-chain payload — no PII, no raw
///         media, no worker identity beyond an optional wallet the worker controls.
/// @dev Adapted from the AgentAudit trust-boundary pattern: a single authorized
///      signer (the backend service) mints; nothing else can. This is explicitly
///      a hackathon-scoped trust model, not a decentralized one — documented as
///      a known limitation, not hidden.
contract FundiAttestation {

    // ============================================================
    // TYPES
    // ============================================================

    /// @dev Kept as a uint8 enum, not a string, to keep on-chain storage cheap
    ///      and to make the "what can this attestation possibly mean" surface
    ///      auditable at the type level rather than by string convention.
    enum AttestationType {
        PpeMissing,      // 0
        ZoneBreach,      // 1
        TrainingComplete // 2
    }

    struct Attestation {
        AttestationType attestationType;
        bytes32 siteHash;        // keccak256(siteId) — site is pseudonymous on-chain
        uint32 severityScore;    // 0-10000, matches Postgres confidence_bp scale
        uint64 timestamp;        // unix seconds, event time not block time
        address subject;         // worker's wallet; address(0) if worker has none yet
    }

    // ============================================================
    // STATE
    // ============================================================

    string public constant name = "Fundi Safety Attestation";
    string public constant symbol = "FUNDI-ATTEST";

    address public immutable issuer;               // the backend's signer address
    uint256 private _nextTokenId;                  // monotonic, starts at 1
    mapping(uint256 => Attestation) private _attestations;
    mapping(uint256 => bool) private _exists;

    // Per-subject index so a worker (or a regulator, given the wallet) can
    // enumerate their own credential history without an off-chain indexer.
    mapping(address => uint256[]) private _tokensBySubject;

    // ============================================================
    // EVENTS
    // ============================================================

    event AttestationMinted(
        uint256 indexed tokenId,
        address indexed subject,
        AttestationType indexed attestationType,
        bytes32 siteHash,
        uint32 severityScore,
        uint64 timestamp
    );

    // ============================================================
    // ERRORS
    // ============================================================

    error NotIssuer();
    error SoulboundTokenNonTransferable();
    error TokenDoesNotExist(uint256 tokenId);
    error SeverityScoreOutOfRange(uint32 provided);

    // ============================================================
    // MODIFIERS
    // ============================================================

    modifier onlyIssuer() {
        if (msg.sender != issuer) revert NotIssuer();
        _;
    }

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    /// @param issuer_ the backend service's signer address (Base Sepolia testnet key,
    ///        never a personal wallet — this is documented in deployment notes).
    constructor(address issuer_) {
        require(issuer_ != address(0), "issuer cannot be zero address");
        issuer = issuer_;
        _nextTokenId = 1; // token IDs start at 1, 0 is reserved as a "no token" sentinel
    }

    // ============================================================
    // MINTING
    // ============================================================

    /// @notice Mints a new soulbound attestation. Callable only by the issuer.
    /// @dev No batching in v1 — one incident/training event maps to one on-chain
    ///      call from the Rust minter. Simpler to reason about and to demo:
    ///      "click here, see the transaction" is the entire wow-moment mechanic.
    function mintAttestation(
        AttestationType attestationType,
        bytes32 siteHash,
        uint32 severityScore,
        uint64 timestamp,
        address subject
    ) external onlyIssuer returns (uint256 tokenId) {
        if (severityScore > 10000) revert SeverityScoreOutOfRange(severityScore);

        tokenId = _nextTokenId;
        _nextTokenId += 1;

        _attestations[tokenId] = Attestation({
            attestationType: attestationType,
            siteHash: siteHash,
            severityScore: severityScore,
            timestamp: timestamp,
            subject: subject
        });
        _exists[tokenId] = true;

        if (subject != address(0)) {
            _tokensBySubject[subject].push(tokenId);
        }

        emit AttestationMinted(
            tokenId,
            subject,
            attestationType,
            siteHash,
            severityScore,
            timestamp
        );
    }

    // ============================================================
    // SOULBOUND ENFORCEMENT
    // ============================================================

    /// @notice Explicitly reverts on any transfer attempt. This contract does NOT
    ///         implement ERC-721's transferFrom/safeTransferFrom/approve as working
    ///         functions — they exist only to fail loudly, so a wallet or marketplace
    ///         that tries to treat this as a normal NFT gets an explicit, named error
    ///         rather than silent unexpected behavior.
    function transferFrom(address, address, uint256) external pure {
        revert SoulboundTokenNonTransferable();
    }

    function safeTransferFrom(address, address, uint256) external pure {
        revert SoulboundTokenNonTransferable();
    }

    function approve(address, uint256) external pure {
        revert SoulboundTokenNonTransferable();
    }

    // ============================================================
    // READ ACCESS
    // ============================================================

    function getAttestation(uint256 tokenId)
        external
        view
        returns (Attestation memory)
    {
        if (!_exists[tokenId]) revert TokenDoesNotExist(tokenId);
        return _attestations[tokenId];
    }

    function tokensOfSubject(address subject)
        external
        view
        returns (uint256[] memory)
    {
        return _tokensBySubject[subject];
    }

    function totalMinted() external view returns (uint256) {
        return _nextTokenId - 1;
    }
}
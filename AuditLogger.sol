// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AuditLogger
 * @dev Smart contract for storing immutable audit records on blockchain
 */
contract AuditLogger {
    
    struct AuditRecord {
        uint256 timestamp;
        uint8 confidenceScore;  // 0-100
        uint8 issueCount;
        bytes32 auditDataHash;  // Hash of complete audit data
        address auditor;        // Address that performed the audit
        bool exists;
    }
    
    // Mapping from contract hash to audit record
    mapping(bytes32 => AuditRecord) public auditRecords;
    
    // Array to keep track of all audited contracts
    bytes32[] public auditedContracts;
    
    // Events
    event AuditLogged(
        bytes32 indexed contractHash,
        address indexed auditor,
        uint256 timestamp,
        uint8 confidenceScore,
        uint8 issueCount,
        bytes32 auditDataHash
    );
    
    event AuditUpdated(
        bytes32 indexed contractHash,
        address indexed auditor,
        uint256 timestamp,
        uint8 confidenceScore
    );
    
    /**
     * @dev Log a new audit record
     * @param _contractHash Hash of the contract code being audited
     * @param _timestamp Unix timestamp of the audit
     * @param _confidenceScore Confidence score of the audit (0-100)
     * @param _issueCount Number of issues found
     * @param _auditDataHash Hash of the complete audit data
     */
    function logAudit(
        bytes32 _contractHash,
        uint256 _timestamp,
        uint8 _confidenceScore,
        uint8 _issueCount,
        bytes32 _auditDataHash
    ) external {
        require(_confidenceScore <= 100, "Confidence score must be <= 100");
        require(_timestamp > 0, "Invalid timestamp");
        require(_auditDataHash != bytes32(0), "Invalid audit data hash");
        
        // If this is the first audit for this contract
        if (!auditRecords[_contractHash].exists) {
            auditedContracts.push(_contractHash);
        }
        
        // Store the audit record
        auditRecords[_contractHash] = AuditRecord({
            timestamp: _timestamp,
            confidenceScore: _confidenceScore,
            issueCount: _issueCount,
            auditDataHash: _auditDataHash,
            auditor: msg.sender,
            exists: true
        });
        
        emit AuditLogged(
            _contractHash,
            msg.sender,
            _timestamp,
            _confidenceScore,
            _issueCount,
            _auditDataHash
        );
    }
    
    /**
     * @dev Get audit record for a specific contract
     * @param _contractHash Hash of the contract code
     * @return AuditRecord struct
     */
    function getAuditRecord(bytes32 _contractHash) 
        external 
        view 
        returns (AuditRecord memory) 
    {
        require(auditRecords[_contractHash].exists, "No audit record found");
        return auditRecords[_contractHash];
    }
    
    /**
     * @dev Check if a contract has been audited
     * @param _contractHash Hash of the contract code
     * @return bool indicating if audit exists
     */
    function isAudited(bytes32 _contractHash) external view returns (bool) {
        return auditRecords[_contractHash].exists;
    }
    
    /**
     * @dev Get the total number of audited contracts
     * @return uint256 count of audited contracts
     */
    function getTotalAuditedContracts() external view returns (uint256) {
        return auditedContracts.length;
    }
    
    /**
     * @dev Get contract hash by index
     * @param _index Index in the auditedContracts array
     * @return bytes32 contract hash
     */
    function getAuditedContractByIndex(uint256 _index) external view returns (bytes32) {
        require(_index < auditedContracts.length, "Index out of bounds");
        return auditedContracts[_index];
    }
    
    /**
     * @dev Get audit summary for a contract
     * @param _contractHash Hash of the contract code
     * @return timestamp, confidenceScore, issueCount, auditor
     */
    function getAuditSummary(bytes32 _contractHash) 
        external 
        view 
        returns (uint256, uint8, uint8, address) 
    {
        require(auditRecords[_contractHash].exists, "No audit record found");
        AuditRecord memory record = auditRecords[_contractHash];
        return (record.timestamp, record.confidenceScore, record.issueCount, record.auditor);
    }
    
    /**
     * @dev Verify audit data integrity
     * @param _contractHash Hash of the contract code
     * @param _auditDataHash Hash to verify against stored hash
     * @return bool indicating if hashes match
     */
    function verifyAuditData(bytes32 _contractHash, bytes32 _auditDataHash) 
        external 
        view 
        returns (bool) 
    {
        if (!auditRecords[_contractHash].exists) {
            return false;
        }
        return auditRecords[_contractHash].auditDataHash == _auditDataHash;
    }
    
    /**
     * @dev Get recent audits (last N audits)
     * @param _count Number of recent audits to return
     * @return arrays of contract hashes, timestamps, and confidence scores
     */
    function getRecentAudits(uint256 _count) 
        external 
        view 
        returns (bytes32[] memory, uint256[] memory, uint8[] memory) 
    {
        uint256 totalAudits = auditedContracts.length;
        uint256 returnCount = _count > totalAudits ? totalAudits : _count;
        
        bytes32[] memory contractHashes = new bytes32[](returnCount);
        uint256[] memory timestamps = new uint256[](returnCount);
        uint8[] memory confidenceScores = new uint8[](returnCount);
        
        for (uint256 i = 0; i < returnCount; i++) {
            bytes32 contractHash = auditedContracts[totalAudits - 1 - i];
            AuditRecord memory record = auditRecords[contractHash];
            
            contractHashes[i] = contractHash;
            timestamps[i] = record.timestamp;
            confidenceScores[i] = record.confidenceScore;
        }
        
        return (contractHashes, timestamps, confidenceScores);
    }
}

/**
 * @title AuditLoggerFactory
 * @dev Factory contract for deploying AuditLogger instances
 */
contract AuditLoggerFactory {
    event AuditLoggerDeployed(address indexed logger, address indexed deployer);
    
    address[] public deployedLoggers;
    mapping(address => address[]) public userLoggers;
    
    function deployAuditLogger() external returns (address) {
        AuditLogger newLogger = new AuditLogger();
        address loggerAddress = address(newLogger);
        
        deployedLoggers.push(loggerAddress);
        userLoggers[msg.sender].push(loggerAddress);
        
        emit AuditLoggerDeployed(loggerAddress, msg.sender);
        
        return loggerAddress;
    }
    
    function getDeployedLoggersCount() external view returns (uint256) {
        return deployedLoggers.length;
    }
    
    function getUserLoggersCount(address _user) external view returns (uint256) {
        return userLoggers[_user].length;
    }
}
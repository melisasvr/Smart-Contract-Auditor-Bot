import hashlib
import json
import re
from datetime import datetime
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
import requests
from web3 import Web3
from eth_account import Account
import openai
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

@dataclass
class SecurityIssue:
    severity: str  # "HIGH", "MEDIUM", "LOW"
    type: str
    description: str
    line_number: int
    suggestion: str

@dataclass
class AuditResult:
    contract_hash: str
    timestamp: str
    confidence_score: float
    issues: List[SecurityIssue]
    overall_assessment: str
    ai_model_used: str

class SolidityAnalyzer:
    """AI-powered Solidity code analyzer"""
    
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.api_key = api_key
        self.model = model
        openai.api_key = api_key
        
        # Basic vulnerability patterns for quick detection
        self.vulnerability_patterns = {
            'reentrancy': [
                r'\.call\s*\(',
                r'\.send\s*\(',
                r'\.transfer\s*\(',
            ],
            'overflow_underflow': [
                r'\+\+',
                r'--',
                r'\+=',
                r'-=',
                r'\*=',
            ],
            'unprotected_function': [
                r'function\s+\w+\s*\([^)]*\)\s*public',
                r'function\s+\w+\s*\([^)]*\)\s*external',
            ],
            'unsafe_delegatecall': [
                r'\.delegatecall\s*\(',
            ],
            'tx_origin': [
                r'tx\.origin',
            ],
            'timestamp_dependence': [
                r'block\.timestamp',
                r'now\b',
            ]
        }

    def quick_scan(self, code: str) -> List[SecurityIssue]:
        """Perform quick pattern-based vulnerability detection"""
        issues = []
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for vuln_type, patterns in self.vulnerability_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        severity = self._get_severity(vuln_type)
                        description = self._get_description(vuln_type)
                        suggestion = self._get_suggestion(vuln_type)
                        
                        issues.append(SecurityIssue(
                            severity=severity,
                            type=vuln_type,
                            description=description,
                            line_number=line_num,
                            suggestion=suggestion
                        ))
        
        return issues

    def ai_analyze(self, code: str) -> Tuple[List[SecurityIssue], float, str]:
        """Use AI to perform deep analysis of the Solidity code"""
        
        prompt = f"""
        Analyze the following Solidity smart contract code for security vulnerabilities.
        Provide a detailed analysis including:
        1. Security issues found (severity: HIGH/MEDIUM/LOW)
        2. Confidence score (0-100)
        3. Overall assessment
        
        Code to analyze:
        ```solidity
        {code}
        ```
        
        Please respond in JSON format:
        {{
            "issues": [
                {{
                    "severity": "HIGH|MEDIUM|LOW",
                    "type": "vulnerability_type",
                    "description": "detailed description",
                    "line_number": 0,
                    "suggestion": "how to fix"
                }}
            ],
            "confidence_score": 85.0,
            "overall_assessment": "summary of findings"
        }}
        """
        
        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a smart contract security expert. Analyze Solidity code for vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            
            result = json.loads(response.choices[0].message.content)
            
            ai_issues = [
                SecurityIssue(**issue) for issue in result.get("issues", [])
            ]
            
            confidence = result.get("confidence_score", 50.0)
            assessment = result.get("overall_assessment", "Analysis completed")
            
            return ai_issues, confidence, assessment
            
        except Exception as e:
            print(f"AI Analysis error: {e}")
            return [], 50.0, "AI analysis failed, using pattern-based detection only"

    def _get_severity(self, vuln_type: str) -> str:
        severity_map = {
            'reentrancy': 'HIGH',
            'unsafe_delegatecall': 'HIGH',
            'tx_origin': 'HIGH',
            'overflow_underflow': 'MEDIUM',
            'unprotected_function': 'MEDIUM',
            'timestamp_dependence': 'LOW'
        }
        return severity_map.get(vuln_type, 'MEDIUM')
    
    def _get_description(self, vuln_type: str) -> str:
        descriptions = {
            'reentrancy': 'Potential reentrancy vulnerability detected',
            'overflow_underflow': 'Potential integer overflow/underflow',
            'unprotected_function': 'Function lacks proper access control',
            'unsafe_delegatecall': 'Unsafe use of delegatecall',
            'tx_origin': 'Use of tx.origin for authorization',
            'timestamp_dependence': 'Dependence on block timestamp'
        }
        return descriptions.get(vuln_type, 'Unknown vulnerability')
    
    def _get_suggestion(self, vuln_type: str) -> str:
        suggestions = {
            'reentrancy': 'Use ReentrancyGuard or checks-effects-interactions pattern',
            'overflow_underflow': 'Use SafeMath library or Solidity 0.8+ built-in checks',
            'unprotected_function': 'Add onlyOwner or appropriate access modifiers',
            'unsafe_delegatecall': 'Validate the target contract and use low-level calls carefully',
            'tx_origin': 'Use msg.sender instead of tx.origin',
            'timestamp_dependence': 'Use block.number or external oracle for timing'
        }
        return suggestions.get(vuln_type, 'Review and fix the identified issue')

class BlockchainLogger:
    """Handles blockchain interactions for storing audit logs"""
    
    def __init__(self, web3_provider: str, contract_address: str, private_key: str):
        self.web3 = None
        self.contract_address = contract_address
        self.account = None
        self.contract = None
        
        # Only initialize blockchain connection if all parameters are provided
        if web3_provider and contract_address and private_key:
            try:
                self.web3 = Web3(Web3.HTTPProvider(web3_provider))
                self.account = Account.from_key(private_key)
                
                # ABI for the audit logging contract
                self.contract_abi = [
                    {
                        "inputs": [
                            {"name": "_contractHash", "type": "bytes32"},
                            {"name": "_timestamp", "type": "uint256"},
                            {"name": "_confidenceScore", "type": "uint8"},
                            {"name": "_issueCount", "type": "uint8"},
                            {"name": "_auditDataHash", "type": "bytes32"}
                        ],
                        "name": "logAudit",
                        "outputs": [],
                        "type": "function"
                    },
                    {
                        "inputs": [{"name": "", "type": "bytes32"}],
                        "name": "auditRecords",
                        "outputs": [
                            {"name": "timestamp", "type": "uint256"},
                            {"name": "confidenceScore", "type": "uint8"},
                            {"name": "issueCount", "type": "uint8"},
                            {"name": "auditDataHash", "type": "bytes32"},
                            {"name": "auditor", "type": "address"}
                        ],
                        "type": "function"
                    }
                ]
                
                self.contract = self.web3.eth.contract(
                    address=contract_address,
                    abi=self.contract_abi
                )
                print("✅ Blockchain connection established")
            except Exception as e:
                print(f"⚠️ Blockchain connection failed: {e}")
                print("📝 Running in mock mode - audit records won't be stored on blockchain")
        else:
            print("📝 Running without blockchain integration")

    def log_audit(self, audit_result: AuditResult) -> str:
        """Store audit result hash on blockchain"""
        try:
            if not self.web3 or not self.contract_address or not self.account:
                return "mock_tx_hash_" + audit_result.contract_hash[:8]
            
            contract_hash = Web3.keccak(text=audit_result.contract_hash)
            audit_data_hash = Web3.keccak(text=json.dumps(asdict(audit_result), sort_keys=True))
            timestamp = int(datetime.now().timestamp())
            confidence_score = min(255, max(0, int(audit_result.confidence_score)))
            issue_count = min(255, len(audit_result.issues))
            
            # Build transaction
            tx = self.contract.functions.logAudit(
                contract_hash,
                timestamp,
                confidence_score,
                issue_count,
                audit_data_hash
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.web3.eth.get_transaction_count(self.account.address),
                'gas': 200000,
                'gasPrice': self.web3.to_wei('20', 'gwei')
            })
            
            # Sign and send transaction
            signed_tx = self.web3.eth.account.sign_transaction(tx, self.account.key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            return tx_hash.hex()
            
        except Exception as e:
            print(f"Blockchain logging error: {e}")
            return f"mock_tx_hash_{audit_result.contract_hash[:8]}"

class SmartContractAuditorBot:
    """Main application class"""
    
    def __init__(self, openai_api_key: str, web3_provider: str = None, 
                 contract_address: str = None, private_key: str = None):
        self.analyzer = SolidityAnalyzer(openai_api_key)
        self.blockchain_logger = BlockchainLogger(web3_provider, contract_address, private_key)
        
    def audit_contract(self, solidity_code: str) -> Tuple[AuditResult, str]:
        """Perform complete audit of Solidity code"""
        
        # Generate hash for the contract
        contract_hash = hashlib.sha256(solidity_code.encode()).hexdigest()
        
        # Quick pattern-based scan
        quick_issues = self.analyzer.quick_scan(solidity_code)
        
        # AI-powered deep analysis
        ai_issues, confidence, assessment = self.analyzer.ai_analyze(solidity_code)
        
        # Combine and deduplicate issues
        all_issues = quick_issues + ai_issues
        unique_issues = self._deduplicate_issues(all_issues)
        
        # Create audit result
        audit_result = AuditResult(
            contract_hash=contract_hash,
            timestamp=datetime.now().isoformat(),
            confidence_score=confidence,
            issues=unique_issues,
            overall_assessment=assessment,
            ai_model_used=self.analyzer.model
        )
        
        # Log to blockchain
        tx_hash = self.blockchain_logger.log_audit(audit_result)
        
        return audit_result, tx_hash
    
    def _deduplicate_issues(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Remove duplicate issues based on type and line number"""
        seen = set()
        unique_issues = []
        
        for issue in issues:
            key = (issue.type, issue.line_number)
            if key not in seen:
                seen.add(key)
                unique_issues.append(issue)
        
        return unique_issues

# Flask Web Application
app = Flask(__name__)
CORS(app)

# Initialize the auditor bot (configure with your API keys)
# For testing without blockchain, set these to None
auditor_bot = SmartContractAuditorBot(
    openai_api_key="your_openai_api_key_here",  # Replace with actual key
    web3_provider=None,  # Set to None for testing without blockchain
    contract_address=None,  # Set to None for testing
    private_key=None  # Set to None for testing
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/audit', methods=['POST'])
def audit_endpoint():
    """API endpoint for contract auditing"""
    try:
        data = request.get_json()
        solidity_code = data.get('code', '')
        
        if not solidity_code.strip():
            return jsonify({'error': 'No code provided'}), 400
        
        # Perform audit
        audit_result, tx_hash = auditor_bot.audit_contract(solidity_code)
        
        # Convert to JSON-serializable format
        response = {
            'audit_result': asdict(audit_result),
            'blockchain_tx': tx_hash,
            'success': True
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    print("🤖 Smart Contract Auditor Bot Starting...")
    print("📝 Make sure to configure your API keys in the code")
    print("🌐 Web interface will be available at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
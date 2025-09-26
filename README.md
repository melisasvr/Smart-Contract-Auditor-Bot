# 🤖 Smart Contract Auditor Bot
- An AI-powered smart contract security analyzer that combines artificial intelligence with blockchain technology to provide automated vulnerability detection for Solidity contracts.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![Solidity](https://img.shields.io/badge/solidity-^0.8.0-orange.svg)
![Web3](https://img.shields.io/badge/web3-enabled-purple.svg)

## 🌟 Features
- **🔍 AI-Powered Analysis**: Uses OpenAI GPT models for deep code analysis
- **⚡ Pattern Recognition**: Quick vulnerability detection using regex patterns
- **🔗 Blockchain Integration**: Immutable audit records stored on-chain
- **🎯 Multi-Vulnerability Detection**: Detects reentrancy, overflow, access control issues, and more
- **📊 Confidence Scoring**: AI-generated reliability metrics
- **🌐 Web Interface**: User-friendly dashboard for code submission and results
- **📈 Real-time Statistics**: Track audit performance and findings

## 🚀 Quick Start
### Prerequisites
- Python 3.8 or higher
- OpenAI API key (for full AI analysis)
- Ethereum wallet and RPC endpoint (for blockchain logging)

### Installation
1. **Clone the repository**
```bash
git clone https://github.com/yourusername/smart-contract-auditor-bot.git
cd smart-contract-auditor-bot
```

2. **Create virtual environment**
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Run the application**
```bash
python app.py
```

5. **Open your browser**
Navigate to `http://localhost:5000`

## 🧪 Testing the Application
### Using Built-in Examples
- The web interface provides quick test examples:
- **Reentrancy Vulnerability**: Classic attack vector
- **Integer Overflow**: Arithmetic vulnerabilities  
- **Access Control Issue**: Missing permissions
- **Timestamp Dependence**: Timing-based issues

### Manual Testing
- Copy and paste this vulnerable contract:

```solidity
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");
        
        // VULNERABLE: External call before state change
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0; // State change after external call
    }
}
```

Click "🔍 Analyze Contract" to see vulnerability detection in action!

## ⚙️ Configuration

### Basic Setup (Pattern Detection Only)

- The app works out of the box with pattern-based detection—no configuration needed for basic functionality.

### Full AI Integration

Create a `.env` file in the project root:

```env
# OpenAI Configuration
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4

# Blockchain Configuration (optional)
WEB3_PROVIDER_URL=https://goerli.infura.io/v3/your_project_id
PRIVATE_KEY=your_private_key_here
CONTRACT_ADDRESS=your_deployed_contract_address
```

### Getting API Keys

1. **OpenAI API Key**: 
   - Visit [OpenAI Platform](https://platform.openai.com/account/api-keys)
   - Create a new API key
   - Add to `.env` file

2. **Ethereum RPC** (for blockchain logging):
   - [Infura](https://infura.io/) - Free tier available
   - [Alchemy](https://alchemy.com/) - Alternative provider
   - [QuickNode](https://quicknode.com/) - Another option

## 🔧 Project Structure

```
smart-contract-auditor-bot/
├── app.py                 # Main Flask application
├── AuditLogger.sol        # Smart contract for blockchain logging
├── templates/
│   └── index.html        # Web interface
├── requirements.txt       # Python dependencies
├── .env                  # Configuration (create this)
├── README.md            # This file
└── deploy.js            # Contract deployment script
```

## 📊 Vulnerability Detection

### Pattern-Based Detection (Always Active)
- **Reentrancy**: External calls before state changes
- **Integer Overflow/Underflow**: Arithmetic operations
- **Access Control**: Missing function modifiers
- **Unsafe Delegatecall**: Dangerous proxy calls
- **TX.Origin Usage**: Authentication bypasses
- **Timestamp Dependence**: Block timing issues

### AI-Enhanced Analysis (Requires API Key)
- **Deep Code Analysis**: Context-aware vulnerability detection
- **Complex Pattern Recognition**: Advanced attack vectors
- **Confidence Scoring**: Reliability assessment
- **Detailed Explanations**: Comprehensive security reports

## 🔗 Blockchain Integration

### Smart Contract Deployment

1. **Install Hardhat**
```bash
npm install --save-dev hardhat @nomiclabs/hardhat-ethers ethers
npx hardhat init
```

2. **Deploy AuditLogger Contract**
```bash
npx hardhat run deploy.js --network goerli
```

3. **Update Configuration**
Add the deployed contract address to your `.env` file.

### Audit Record Storage

Each audit creates an immutable blockchain record containing:
- Contract code hash
- Timestamp
- Confidence score
- Issue count
- Audit data hash
- Auditor address

## 📈 Expected Results

### Pattern Detection Working
```
🚨 Security Issues Found
REENTRANCY - HIGH
Line 14: Potential reentrancy vulnerability detected
Fix: Use ReentrancyGuard or checks-effects-interactions pattern

UNPROTECTED FUNCTION - MEDIUM  
Line 6: Function lacks proper access control
Fix: Add onlyOwner or appropriate access modifiers
```

### AI Analysis (with API key)
```
Confidence Score: 85%
Overall Assessment: The Contract contains a critical reentrancy vulnerability 
that could lead to fund drainage. Immediate fix required.
```

### Mock Mode (without blockchain)
```
🔗 Blockchain Record
Audit record stored on blockchain:
mock_tx_hash_a1b2c3d4
This creates an immutable audit trail
```

## 🛠️ Development

### Requirements

```
Flask==2.3.3
Flask-CORS==4.0.0
web3==6.11.0
eth-account==0.9.0
openai==0.28.1
requests==2.31.0
python-dotenv==1.0.0
gunicorn==21.2.0
```

### Running in Development Mode

```bash
export FLASK_ENV=development
export FLASK_DEBUG=True
python app.py
```

### Testing

Run unit tests:
```bash
python -m pytest tests/
```

## 🚧 Troubleshooting

### Common Issues

**1. Private Key Error**
```
ValueError: The private key must be exactly 32 bytes long
```
**Solution**: Set blockchain parameters to `None` in `app.py` for testing without blockchain.

**2. OpenAI API Error**
```
Incorrect API key provided
```
**Solution**: Add a valid OpenAI API key to the `.env` file or test with pattern detection only.

**3. Port Already in Use**
```
OSError: [Errno 48] Address already in use
```
**Solution**: Kill the process on port 5000 or change the port in `app.py`.

## 🔒 Security Considerations

### Development
- ⚠️ Never commit API keys to version control
- ⚠️ Use test networks only during development
- ⚠️ Keep private keys secure and separate

### Production
- 🔐 Use environment variables for sensitive data
- 🔐 Implement rate limiting for API endpoints
- 🔐 Use HTTPS for all communications
- 🔐 Regular security audits of the auditor itself

## 🚀 Deployment Options

### Local Development
```bash
python app.py
```

### Production with Gunicorn
```bash
gunicorn --bind 0.0.0.0:5000 app:app
```

### Docker
```bash
docker build -t smart-contract-auditor.
docker run -p 5000:5000 smart-contract-auditor
```

### Cloud Platforms
- **Heroku**: Git-based deployment
- **AWS ECS**: Container deployment
- **Google Cloud Run**: Serverless containers
- **DigitalOcean**: App platform deployment

## 🤝 Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License
- This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments
- OpenAI for GPT models
- Ethereum community for Web3 tools
- Flask team for the web framework
- Contributors and testers

---
**⚡ Quick Test**: Run `python app.py`, open `http://localhost:5000`, click "Reentrancy Vulnerability", then "Analyze Contract" to see it in action!
- Made with ❤️ for the Web3 security community

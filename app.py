import os
import json
import time
import uuid
import logging
import hashlib
import base64
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from functools import wraps
from flask import Flask, render_template, request, jsonify, abort, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from eth_account import Account
from eth_account.messages import encode_defunct
from cryptography.fernet import Fernet, InvalidToken
import requests
from requests.exceptions import RequestException
from threading import Lock
import jwt
from dotenv import load_dotenv

# Initialize Flask app
app = Flask(
    __name__,
    static_url_path='/static',
    static_folder='static',
    template_folder='templates'
)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', str(uuid.uuid4()))
CORS(app, resources={r"/api/*": {"origins": "http://127.0.0.1:5000"}})

# Load environment variables
load_dotenv()

# Configuration
CONFIG = {
    "WALLET_FILE": "wallet.json",
    "ENCRYPTION_KEY_FILE": "encryption.key",
    "LOG_DIR": "wallet_logs",
    "COIN_GECKO_API": "https://api.coingecko.com/api/v3",
    "NETWORK_PROVIDERS": {
        "ethereum": "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID",
        "bsc": "https://bsc-dataseed.binance.org/",
        "polygon": "https://polygon-rpc.com/",
        "beldex": "https://rpc.beldex.io"  # Placeholder
    },
    "SUPPORTED_COINS": {
        "bitcoin": {"name": "Bitcoin", "symbol": "BTC", "logo": "btc.png", "network": "bitcoin"},
        "ethereum": {"name": "Ethereum", "symbol": "ETH", "logo": "eth.png", "network": "ethereum"},
        "usdt": {"name": "Tether", "symbol": "USDT", "logo": "usdt.png", "network": "ethereum"},
        "usdc": {"name": "USD Coin", "symbol": "USDC", "logo": "usdc.png", "network": "ethereum"}
    },
    "TOKEN_ABI": [
        {
            "constant": True,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [],
            "name": "name",
            "outputs": [{"name": "", "type": "string"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [],
            "name": "symbol",
            "outputs": [{"name": "", "type": "string"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [],
            "name": "decimals",
            "outputs": [{"name": "", "type": "uint8"}],
            "type": "function"
        }
    ],
    "JWT_EXPIRY_HOURS": 24,
    "RATE_LIMIT": "100 per hour"
}

# Setup logging
Path(CONFIG["LOG_DIR"]).mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s - [PID:%(process)d TID:%(thread)d]',
    handlers=[
        logging.FileHandler(
            f"{CONFIG['LOG_DIR']}/wallet_server_{datetime.now().strftime('%Y%m%d')}.log",
            encoding='utf-8'
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=[CONFIG["RATE_LIMIT"]]
)

# Thread-safe wallet access
wallet_lock = Lock()

# User database (in-memory for demo; use SQLAlchemy for production)
users: Dict[str, Dict] = {}

class WalletError(Exception):
    """Custom exception for wallet errors."""
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

def require_auth(f):
    """Decorator for JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            raise WalletError("Authentication token missing", 401)
        try:
            token = token.replace('Bearer ', '')
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            request.user_id = data['user_id']
        except jwt.InvalidTokenError:
            raise WalletError("Invalid token", 401)
        return f(*args, **kwargs)
    return decorated

def validate_address(address: str, network: str) -> bool:
    """Validate blockchain address format."""
    if network == "bitcoin":
        return len(address) >= 26 and len(address) <= 62 and address.startswith(('1', '3', 'bc1'))
    elif network in ["ethereum", "bsc", "polygon"]:
        return Web3.is_address(address)
    elif network == "beldex":
        return len(address) == 98 and address.startswith('b')  # Placeholder
    return False

def load_encryption_key() -> bytes:
    """Load or generate encryption key."""
    key_file = Path(CONFIG["ENCRYPTION_KEY_FILE"])
    try:
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        logger.info("Generated new encryption key")
        return key
    except Exception as e:
        logger.error(f"Error handling encryption key: {e}")
        raise WalletError("Failed to manage encryption key", 500)

def encrypt_data(data: str, key: bytes) -> str:
    """Encrypt data with Fernet."""
    try:
        fernet = Fernet(key)
        return fernet.encrypt(data.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise WalletError("Encryption error", 500)

def decrypt_data(encrypted_data: str, key: bytes) -> str:
    """Decrypt data with Fernet."""
    try:
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data.encode()).decode()
    except InvalidToken:
        logger.error("Invalid decryption token")
        raise WalletError("Invalid password or corrupted data", 401)
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise WalletError("Decryption error", 500)

def load_wallet(user_id: str, password: str) -> Optional[Account]:
    """Load wallet from file."""
    with wallet_lock:
        try:
            wallet_file = Path(CONFIG["WALLET_FILE"])
            if not wallet_file.exists():
                return None
            with open(wallet_file, 'r') as f:
                wallets = json.load(f)
            user_wallet = wallets.get(user_id)
            if not user_wallet:
                return None
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), base64.b64decode(user_wallet['salt']), 100000)
            private_key = decrypt_data(user_wallet['private_key'], base64.b64encode(key).decode())
            account = Account.from_key(private_key)
            logger.info(f"Loaded wallet for user {user_id}")
            return account
        except Exception as e:
            logger.error(f"Error loading wallet for user {user_id}: {e}")
            return None

def save_wallet(user_id: str, account: Account, password: str):
    """Save wallet to file."""
    with wallet_lock:
        try:
            wallet_file = Path(CONFIG["WALLET_FILE"])
            wallets = {}
            if wallet_file.exists():
                with open(wallet_file, 'r') as f:
                    wallets = json.load(f)
            salt = base64.b64encode(os.urandom(16)).decode()
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), base64.b64decode(salt), 100000)
            encrypted_key = encrypt_data(account.key.hex(), base64.b64encode(key).decode())
            wallets[user_id] = {
                "address": account.address,
                "private_key": encrypted_key,
                "salt": salt
            }
            with open(wallet_file, 'w') as f:
                json.dump(wallets, f, indent=4)
            logger.info(f"Saved wallet for user {user_id}")
        except Exception as e:
            logger.error(f"Error saving wallet for user {user_id}: {e}")
            raise WalletError("Failed to save wallet", 500)

def get_web3_instance(network: str) -> Web3:
    """Initialize Web3 instance for a network."""
    try:
        url = CONFIG["NETWORK_PROVIDERS"].get(network)
        if not url:
            raise WalletError(f"Unsupported network: {network}", 400)
        w3 = Web3(HTTPProvider(url))
        if network in ["bsc", "polygon"]:
            w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        if not w3.is_connected():
            raise WalletError(f"Failed to connect to {network}", 503)
        return w3
    except Exception as e:
        logger.error(f"Error initializing Web3 for {network}: {e}")
        raise WalletError(f"Network error: {str(e)}", 500)

@app.errorhandler(WalletError)
def handle_wallet_error(error: WalletError):
    """Handle custom wallet errors."""
    response = jsonify({"error": error.message})
    response.status_code = error.status_code
    return response

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors."""
    logger.error(f"Server error: {error}")
    return jsonify({"error": "Internal server error"}), 500

@app.route('/api/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    """Register a new user."""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            raise WalletError("Username and password required", 400)
        if username in users:
            raise WalletError("Username already exists", 409)
        users[username] = {
            "user_id": str(uuid.uuid4()),
            "password_hash": generate_password_hash(password),
            "created_at": datetime.utcnow().isoformat()
        }
        token = jwt.encode(
            {
                "user_id": users[username]["user_id"],
                "exp": datetime.utcnow() + timedelta(hours=CONFIG["JWT_EXPIRY_HOURS"])
            },
            app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        logger.info(f"Registered user: {username}")
        return jsonify({"token": token, "user_id": users[username]["user_id"]})
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        raise WalletError(str(e), 500)

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """Login a user."""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            raise WalletError("Username and password required", 400)
        user = users.get(username)
        if not user or not check_password_hash(user["password_hash"], password):
            raise WalletError("Invalid credentials", 401)
        token = jwt.encode(
            {
                "user_id": user["user_id"],
                "exp": datetime.utcnow() + timedelta(hours=CONFIG["JWT_EXPIRY_HOURS"])
            },
            app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        logger.info(f"User logged in: {username}")
        return jsonify({"token": token, "user_id": user["user_id"]})
    except Exception as e:
        logger.error(f"Error logging in: {e}")
        raise WalletError(str(e), 500)

@app.route('/api/create-wallet', methods=['POST'])
@require_auth
@limiter.limit("5 per minute")
def create_wallet():
    """Create a new wallet for the user."""
    try:
        data = request.get_json()
        password = data.get('password')
        user_id = request.user_id
        if not password:
            raise WalletError("Password required", 400)
        account = Account.create()
        save_wallet(user_id, account, password)
        # Generate seed phrase (BIP-39)
        seed_phrase = " ".join(Account._mnemonic_from_entropy(os.urandom(16)))
        logger.info(f"Created wallet for user {user_id}: {account.address}")
        return jsonify({"address": account.address, "seedPhrase": seed_phrase})
    except Exception as e:
        logger.error(f"Error creating wallet: {e}")
        raise WalletError(str(e), 500)

@app.route('/api/restore-wallet', methods=['POST'])
@require_auth
@limiter.limit("5 per minute")
def restore_wallet():
    """Restore wallet from seed phrase."""
    try:
        data = request.get_json()
        password = data.get('password')
        seed_phrase = data.get('seedPhrase')
        user_id = request.user_id
        if not password or not seed_phrase:
            raise WalletError("Password and seed phrase required", 400)
        try:
            account = Account.from_mnemonic(seed_phrase)
        except ValueError:
            raise WalletError("Invalid seed phrase", 400)
        save_wallet(user_id, account, password)
        logger.info(f"Restored wallet for user {user_id}: {account.address}")
        return jsonify({"address": account.address})
    except Exception as e:
        logger.error(f"Error restoring wallet: {e}")
        raise WalletError(str(e), 500)

@app.route('/api/balance', methods=['POST'])
@require_auth
@limiter.limit("20 per minute")
def get_balance():
    """Get wallet balance for a coin."""
    try:
        data = request.get_json()
        address = data.get('address')
        coin = data.get('coin', '').upper()
        network = data.get('network', 'ethereum')
        user_id = request.user_id
        if not address or not coin:
            raise WalletError("Address and coin required", 400)
        if not validate_address(address, network):
            raise WalletError("Invalid address format", 400)
        coin_data = CONFIG["SUPPORTED_COINS"].get(coin.lower())
        if not coin_data:
            raise WalletError("Unsupported coin", 400)
        w3 = get_web3_instance(network)
        if coin_data["network"] == "bitcoin":
            # Placeholder: Use Bitcoin API
            return jsonify({"balance": "0", "symbol": coin})
        elif coin_data["network"] in ["ethereum", "bsc", "polygon"]:
            if coin in ["ETH", "BNB", "MATIC"]:
                balance = w3.eth.get_balance(address)
                balance_wei = w3.from_wei(balance, 'ether')
                logger.info(f"Fetched balance for {address}: {balance_wei} {coin}")
                return jsonify({"balance": str(balance_wei), "symbol": coin})
            else:
                # ERC-20 token
                contract = w3.eth.contract(address=Web3.to_checksum_address(coin_data["contract"]), abi=CONFIG["TOKEN_ABI"])
                balance = contract.functions.balanceOf(address).call()
                decimals = contract.functions.decimals().call()
                balance_token = balance / (10 ** decimals)
                logger.info(f"Fetched token balance for {address}: {balance_token} {coin}")
                return jsonify({"balance": str(balance_token), "symbol": coin})
        else:
            raise WalletError("Unsupported network for coin", 400)
    except Exception as e:
        logger.error(f"Error fetching balance: {e}")
        raise WalletError(str(e), 500)

@app.route('/api/send-transaction', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def send_transaction():
    """Send a transaction."""
    try:
        data = request.get_json()
        recipient = data.get('recipient')
        amount = float(data.get('amount', 0))
        coin = data.get('coin', '').upper()
        network = data.get('network')
        password = data.get('password')
        user_id = request.user_id
        if not all([recipient, amount, coin, network, password]):
            raise WalletError("All fields required", 400)
        if not validate_address(recipient, network):
            raise WalletError("Invalid recipient address", 400)
        account = load_wallet(user_id, password)
        if not account:
            raise WalletError("Invalid password or wallet not found", 401)
        w3 = get_web3_instance(network)
        if coin in ["ETH", "BNB", "MATIC"]:
            nonce = w3.eth.get_transaction_count(account.address)
            tx = {
                'nonce': nonce,
                'to': Web3.to_checksum_address(recipient),
                'value': w3.to_wei(amount, 'ether'),
                'gas': 21000,
                'gasPrice': w3.to_wei('50', 'gwei'),
                'chainId': 1 if network == "ethereum" else 56 if network == "bsc" else 137
            }
            signed_tx = account.sign_transaction(tx)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            logger.info(f"Sent transaction from {account.address} to {recipient}: {tx_hash.hex()}")
            return jsonify({"txHash": tx_hash.hex()})
        else:
            raise WalletError("Token transactions not implemented", 501)
    except Exception as e:
        logger.error(f"Error sending transaction: {e}")
        raise WalletError(str(e), 500)

@app.route('/api/tokens', methods=['POST'])
@require_auth
@limiter.limit("20 per minute")
def get_tokens():
    """Get token balances for a wallet."""
    try:
        data = request.get_json()
        address = data.get('address')
        network = data.get('network')
        user_id = request.user_id
        if not address or not network:
            raise WalletError("Address and network required", 400)
        if not validate_address(address, network):
            raise WalletError("Invalid address format", 400)
        w3 = get_web3_instance(network)
        tokens = []
        for coin, meta in CONFIG["SUPPORTED_COINS"].items():
            if meta["network"] == network and coin not in ["ethereum", "bnb", "matic"]:
                contract = w3.eth.contract(address=Web3.to_checksum_address(meta["contract"]), abi=CONFIG["TOKEN_ABI"])
                balance = contract.functions.balanceOf(address).call()
                decimals = contract.functions.decimals().call()
                balance_token = balance / (10 ** decimals)
                tokens.append({
                    "name": meta["name"],
                    "symbol": meta["symbol"],
                    "balance": str(balance_token)
                })
        logger.info(f"Fetched tokens for {address} on {network}")
        return jsonify({"tokens": tokens})
    except Exception as e:
        logger.error(f"Error fetching tokens: {e}")
        raise WalletError(str(e), 500)

@app.route('/api/add-token', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def add_token():
    """Add a new token to the wallet."""
    try:
        data = request.get_json()
        token_address = data.get('tokenAddress')
        network = data.get('network')
        user_id = request.user_id
        if not token_address or not network:
            raise WalletError("Token address and network required", 400)
        if not Web3.is_address(token_address):
            raise WalletError("Invalid token address", 400)
        w3 = get_web3_instance(network)
        contract = w3.eth.contract(address=Web3.to_checksum_address(token_address), abi=CONFIG["TOKEN_ABI"])
        symbol = contract.functions.symbol().call()
        name = contract.functions.name().call()
        decimals = contract.functions.decimals().call()
        # Update supported coins (in-memory; persist in production)
        CONFIG["SUPPORTED_COINS"][symbol.lower()] = {
            "name": name,
            "symbol": symbol,
            "logo": "generic.png",
            "network": network,
            "contract": token_address
        }
        logger.info(f"Added token {symbol} for user {user_id} on {network}")
        return jsonify({"success": True, "symbol": symbol})
    except Exception as e:
        logger.error(f"Error adding token: {e}")
        raise WalletError(str(e), 500)

@app.route('/api/transactions', methods=['POST'])
@require_auth
@limiter.limit("20 per minute")
def get_transactions():
    """Get transaction history for a wallet."""
    try:
        data = request.get_json()
        address = data.get('address')
        network = data.get('network')
        user_id = request.user_id
        if not address or not network:
            raise WalletError("Address and network required", 400)
        if not validate_address(address, network):
            raise WalletError("Invalid address format", 400)
        # Placeholder: Use blockchain explorer API
        transactions = [
            {
                "hash": f"0x{hashlib.sha256(str(i).encode()).hexdigest()[:64]}",
                "amount": f"{0.1 * (i + 1)}",
                "coin": "ETH" if network == "ethereum" else "BNB" if network == "bsc" else "MATIC",
                "status": "Confirmed"
            } for i in range(5)
        ]
        logger.info(f"Fetched transactions for {address} on {network}")
        return jsonify({"transactions": transactions})
    except Exception as e:
        logger.error(f"Error fetching transactions: {e}")
        raise WalletError(str(e), 500)

@app.route('/api/ai-explain', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def ai_explain():
    """Provide AI explanation for crypto-related text."""
    try:
        data = request.get_json()
        text = data.get('text')
        user_id = request.user_id
        if not text:
            raise WalletError("Text required", 400)
        # Placeholder: Integrate with AI service (e.g., Grok API)
        explanation = (
            f"Kamran Crypto Wallet AI Analysis:\n"
            f"Input: {text}\n"
            f"Explanation: This is a placeholder response. For a real implementation, an AI model would analyze the input, "
            f"identify if it's an address, transaction hash, or other crypto data, and provide detailed insights. For example, "
            f"if '{text}' is an Ethereum address, the AI could fetch transaction history or verify its validity."
        )
        logger.info(f"Generated AI explanation for user {user_id}")
        return jsonify({"explanation": explanation})
    except Exception as e:
        logger.error(f"Error in AI explanation: {e}")
        raise WalletError(str(e), 500)

@app.route('/api/coin-prices', methods=['GET'])
@limiter.limit("30 per minute")
def get_coin_prices():
    """Fetch live coin prices from CoinGecko."""
    try:
        url = f"{CONFIG['COIN_GECKO_API']}/simple/price"
        params = {
            "ids": ','.join(CONFIG["SUPPORTED_COINS"].keys()),
            "vs_currencies": "usd"
        }
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        prices = response.json()
        coins_data = []
        for key, meta in CONFIG["SUPPORTED_COINS"].items():
            coin_price = prices.get(key, {}).get("usd", 0)
            coins_data.append({
                "symbol": meta["symbol"],
                "name": meta["name"],
                "price": f"${coin_price:,.2f}",
                "logo": f"/static/{meta['logo']}"
            })
        logger.info("Fetched coin prices from CoinGecko")
        return jsonify({"coins": coins_data})
    except RequestException as e:
        logger.error(f"Error fetching coin prices: {e}")
        raise WalletError(f"Failed to fetch coin prices: {str(e)}", 500)

@app.route('/', methods=['GET'])
def index():
    """Render the wallet homepage."""
    try:
        coins_data = []
        try:
            url = f"{CONFIG['COIN_GECKO_API']}/simple/price"
            params = {
                "ids": ','.join(CONFIG["SUPPORTED_COINS"].keys()),
                "vs_currencies": "usd"
            }
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            prices = response.json()
            for key, meta in CONFIG["SUPPORTED_COINS"].items():
                coin_price = prices.get(key, {}).get("usd", 0)
                coins_data.append({
                    "symbol": meta["symbol"],
                    "name": meta["name"],
                    "price": f"${coin_price:,.2f}",
                    "logo": f"/static/{meta['logo']}"
                })
        except RequestException as e:
            logger.warning(f"Failed to fetch coin prices: {e}")
            coins_data = [
                {
                    "symbol": meta["symbol"],
                    "name": meta["name"],
                    "price": "$0.00",
                    "logo": f"/static/{meta['logo']}"
                } for meta in CONFIG["SUPPORTED_COINS"].values()
            ]
        logger.info("Rendered wallet homepage")
        return render_template("index.html", coins=coins_data)
    except Exception as e:
        logger.error(f"Error rendering homepage: {e}")
        raise WalletError(f"Failed to load homepage: {str(e)}", 500)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Check server health."""
    try:
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "networks": list(CONFIG["NETWORK_PROVIDERS"].keys())
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

def initialize_server():
    """Initialize server configurations."""
    try:
        logger.info("Initializing Kamran Crypto Wallet Server")
        # Ensure required directories exist
        Path(CONFIG["LOG_DIR"]).mkdir(exist_ok=True)
        Path('static').mkdir(exist_ok=True)
        Path('templates').mkdir(exist_ok=True)
        # Ensure encryption key exists
        load_encryption_key()
        # Initialize supported coins with contract addresses (for ERC-20 tokens)
        CONFIG["SUPPORTED_COINS"]["usdt"]["contract"] = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        CONFIG["SUPPORTED_COINS"]["usdc"]["contract"] = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        logger.info("Server initialized successfully")
    except Exception as e:
        logger.error(f"Server initialization failed: {e}")
        raise

if __name__ == '__main__':
    initialize_server()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
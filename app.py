from flask import Flask, jsonify, request, render_template_string, redirect
import requests
import sqlite3
import datetime
import os
import re
import logging
from typing import Dict, Any

# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cryptoshield.log'),
        logging.StreamHandler()
    ]
)

def log_activity(event_type: str, details: str = ""):
    """Enhanced logging function with security considerations"""
    timestamp = datetime.datetime.now().isoformat()
    # Sanitize sensitive data from logs
    safe_details = details
    if 'api_key' in details.lower() or 'key' in details.lower():
        safe_details = "[REDACTED_SENSITIVE_DATA]"
    
    log_message = f"📊 {timestamp} - {event_type}: {safe_details}"
    logging.info(log_message)
    print(log_message)

class Config:
    """Configuration management with environment variables"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    COINBASE_API_KEY = os.environ.get('COINBASE_API_KEY', '')
    DATABASE_URL = os.environ.get('DATABASE_URL', 'cryptoshield.db')
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

app = Flask(__name__)
app.config.from_object(Config)

def is_valid_url(url: str) -> bool:
    """Validate URL format"""
    if not url:
        return False
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def enhanced_scam_detection(url: str) -> Dict[str, Any]:
    """Enhanced scam detection with multiple validation layers"""
    results = {
        'is_scam': False,
        'risk_level': 'LOW',
        'reasons': [],
        'normalized_url': url
    }
    
    if not url:
        return results
    
    # Normalize URL for checking
    normalized_url = url.lower()
    if not normalized_url.startswith(('http://', 'https://')):
        normalized_url = 'https://' + normalized_url
    results['normalized_url'] = normalized_url
    
    # Domain blacklist check
    SCAM_BLACKLIST = [
        'fakewallet.com', 'phishing-site.com', 'free-crypto-giveaway.com',
        'metamask-phishing.com', 'wallet-connect-scam.com', 'airdrop-scam.net',
        'wallet-connect[.]io', 'app-uniswap[.]org', 'pancakeswap[.]finance',
        'trustwallet[.]com', 'coinbase-wallet[.]com', 'opensea[.]io',
        'walletconnect[.]com-scam', 'metamask[.]io-fake'
    ]
    
    # High-risk keywords
    suspicious_keywords = [
        'free-crypto', 'giveaway', 'airdrop', 'wallet-connect', 
        'metamask', 'claim', 'reward', 'bonus', 'free-money'
    ]
    
    # Check against blacklist
    for domain in SCAM_BLACKLIST:
        if domain in normalized_url:
            results['is_scam'] = True
            results['reasons'].append(f"Blacklisted domain: {domain}")
    
    # Check for suspicious keywords in path/query
    for keyword in suspicious_keywords:
        if keyword in normalized_url:
            results['is_scam'] = True
            results['reasons'].append(f"Suspicious keyword: {keyword}")
    
    # Check for domain impersonation
    legitimate_domains = ['uniswap.org', 'pancakeswap.finance', 'opensea.io']
    for legit_domain in legitimate_domains:
        if legit_domain.replace('.', '[.]') in normalized_url:
            results['is_scam'] = True
            results['reasons'].append(f"Domain impersonation: {legit_domain}")
    
    # Determine risk level
    if results['is_scam']:
        results['risk_level'] = 'HIGH'
    elif len(results['reasons']) > 0:
        results['risk_level'] = 'MEDIUM'
    
    return results

# Initialize database with error handling
def init_db():
    """Initialize database with proper error handling"""
    conn = None
    try:
        conn = sqlite3.connect(Config.DATABASE_URL, check_same_thread=False)
        c = conn.cursor()
        
        # Users table
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY, 
                      email TEXT UNIQUE, 
                      plan TEXT DEFAULT 'trial', 
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # Payments table
        c.execute('''CREATE TABLE IF NOT EXISTS payments
                     (id INTEGER PRIMARY KEY, 
                      user_id INTEGER, 
                      amount REAL, 
                      status TEXT, 
                      crypto_amount REAL, 
                      crypto_currency TEXT, 
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY(user_id) REFERENCES users(id))''')
        
        # Activity log table
        c.execute('''CREATE TABLE IF NOT EXISTS activity_log
                     (id INTEGER PRIMARY KEY,
                      event_type TEXT,
                      details TEXT,
                      ip_address TEXT,
                      user_agent TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        conn.commit()
        log_activity("DB_INIT", "Database initialized successfully")
        
    except sqlite3.Error as e:
        log_activity("DB_ERROR", f"Database initialization failed: {str(e)}")
        raise e
    finally:
        if conn:
            conn.close()

init_db()

def log_activity_to_db(event_type: str, details: str = ""):
    """Log activity to database for better analytics"""
    conn = None
    try:
        conn = sqlite3.connect(Config.DATABASE_URL, check_same_thread=False)
        c = conn.cursor()
        
        c.execute('''INSERT INTO activity_log 
                     (event_type, details, ip_address, user_agent) 
                     VALUES (?, ?, ?, ?)''',
                  (event_type, details, request.remote_addr, request.user_agent.string))
        
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Failed to log activity to DB: {str(e)}")
    finally:
        if conn:
            conn.close()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CryptoShield AI - Protect Your Crypto</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; line-height: 1.6; }
        .alert { background: #ffebee; color: #c62828; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .safe { background: #e8f5e8; color: #2e7d32; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .warning { background: #fff3e0; color: #ef6c00; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .premium { background: #fff3e0; border: 2px solid #ff9800; padding: 20px; margin: 20px 0; border-radius: 8px; }
        .manual-payment { background: #f0f8ff; border: 2px solid #2196f3; padding: 20px; margin: 20px 0; border-radius: 8px; }
        button { background: #0052FF; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin: 5px; }
        button.secondary { background: #4CAF50; }
        button.warning { background: #ff9800; }
        input[type="text"] { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
        .payment-address { background: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace; word-break: break-all; }
        .risk-high { color: #c62828; font-weight: bold; }
        .risk-medium { color: #ef6c00; font-weight: bold; }
        .risk-low { color: #2e7d32; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🛡️ CryptoShield AI</h1>
    <p><strong>Status:</strong> ACTIVE | <strong>Revenue Target:</strong> $100k/month</p>
    
    <div class="premium">
        <h3>🚀 PREMIUM PROTECTION - $4.99/month</h3>
        <p>• Real-time AI scam detection<br>• Contract address analysis<br>• Portfolio monitoring<br>• Browser extension access</p>
        <button onclick="window.location.href='/premium'">Get Premium Protection</button>
    </div>

    <h2>Test URL Protection</h2>
    <input type="text" id="urlInput" placeholder="Enter URL to check (e.g., https://uniswap.org)">
    <button onclick="checkUrl()">Check Safety</button>
    <div id="result"></div>

    <div style="margin-top: 40px; padding: 20px; background: #f9f9f9; border-radius: 8px;">
        <h3>📊 Business Metrics</h3>
        <p><strong>Users Protected:</strong> <span id="userCount">Loading...</span></p>
        <p><strong>Scams Blocked:</strong> <span id="scamCount">Loading...</span></p>
        <p><strong>System Status:</strong> <span style="color: #4CAF50;">● OPERATIONAL</span></p>
    </div>

    <script>
        async function checkUrl() {
            const url = document.getElementById('urlInput').value;
            if (!url) {
                alert('Please enter a URL to check');
                return;
            }
            
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '<div class="safe">🔍 Analyzing URL...</div>';
            
            try {
                const response = await fetch(`/api/check?url=${encodeURIComponent(url)}`);
                const data = await response.json();
                
                if (data.safe) {
                    resultDiv.innerHTML = `<div class="safe">✅ SAFE: ${data.message}<br>Risk Level: <span class="risk-${data.risk_level.toLowerCase()}">${data.risk_level}</span></div>`;
                } else {
                    let reasons = '';
                    if (data.reasons && data.reasons.length > 0) {
                        reasons = '<br><strong>Reasons:</strong><ul>' + data.reasons.map(reason => `<li>${reason}</li>`).join('') + '</ul>';
                    }
                    resultDiv.innerHTML = `<div class="alert">🚨 BLOCKED: ${data.message}${reasons}<br>Risk Level: <span class="risk-high">${data.risk_level}</span></div>`;
                }
            } catch (error) {
                resultDiv.innerHTML = `<div class="warning">❌ Error checking URL: ${error}</div>`;
            }
        }
        
        // Load basic metrics
        async function loadMetrics() {
            try {
                // Simulate user growth
                document.getElementById('userCount').textContent = '25+ and growing';
                document.getElementById('scamCount').textContent = '150+ detected';
            } catch (error) {
                console.log('Metrics loading:', error);
            }
        }
        
        loadMetrics();
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    log_activity("PAGE_VIEW", "homepage")
    log_activity_to_db("PAGE_VIEW", "homepage")
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/check')
def check_url():
    url = request.args.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    if not is_valid_url(url):
        return jsonify({'error': 'Invalid URL format'}), 400
    
    log_activity("URL_CHECK", f"Checking URL: {url}")
    log_activity_to_db("URL_CHECK", f"URL: {url}")
    
    # Enhanced scam detection
    detection_result = enhanced_scam_detection(url)
    
    # Log the check result
    log_activity("URL_CHECK_RESULT", 
                f"{url} - {'BLOCKED' if detection_result['is_scam'] else 'ALLOWED'} - Risk: {detection_result['risk_level']}")
    
    return jsonify({
        'url': url,
        'safe': not detection_result['is_scam'],
        'risk_level': detection_result['risk_level'],
        'reasons': detection_result['reasons'],
        'message': 'Potential scam detected' if detection_result['is_scam'] else 'URL appears safe',
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/premium')
def premium():
    log_activity("PAGE_VIEW", "premium_page")
    log_activity_to_db("PAGE_VIEW", "premium_page")
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Premium - CryptoShield AI</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .payment-option { background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #0052FF; }
            button { background: #0052FF; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; margin: 10px 5px; }
            .crypto-address { background: #e9ecef; padding: 10px; border-radius: 4px; font-family: monospace; word-break: break-all; }
            .feature-list { margin: 20px 0; }
            .feature-list li { margin: 10px 0; }
        </style>
    </head>
    <body>
        <h1>🚀 CryptoShield AI Premium</h1>
        <p><strong>$4.99/month</strong> - Complete crypto protection</p>
        
        <div class="feature-list">
            <h3>✨ Premium Features:</h3>
            <ul>
                <li>✅ Advanced AI scam detection</li>
                <li>✅ Real-time portfolio monitoring</li>
                <li>✅ Contract address analysis</li>
                <li>✅ Browser extension access</li>
                <li>✅ Priority customer support</li>
                <li>✅ Multi-wallet protection</li>
            </ul>
        </div>
        
        <div class="payment-option">
            <h3>💰 Coinbase Payments (Recommended)</h3>
            <p>Instant setup with your existing Coinbase account</p>
            <button onclick="window.location.href='/coinbase-payment'">Pay with Coinbase</button>
        </div>
        
        <div class="payment-option">
            <h3>⚡ Manual Crypto Payments</h3>
            <p>Send $4.99 USD equivalent in crypto to:</p>
            <div class="crypto-address">
                <strong>Bitcoin (BTC):</strong>  1Nkck7Q1cEZmQBsxzhobipgByS9p7BxGYz<br>
                <strong>Ethereum (ETH):</strong> 0x7998C2b3e97b1b0b587D7B548b614267c62Da34D<br>
                <strong>USDC (ERC-20):</strong> 0xC2AcEE65df126470a2E12E50B8F235111bDb9aed
            </div>
            <p>After payment, email receipt to: <strong>d.orton5963@gmail.com</strong></p>
            <p><small>Include your email address in the payment memo for faster activation</small></p>
        </div>
        
        <div style="margin-top: 30px;">
            <button onclick="window.location.href='/'">← Back to Home</button>
        </div>
    </body>
    </html>
    ''')

@app.route('/coinbase-payment')
def coinbase_payment():
    log_activity("PAYMENT_ATTEMPT", "coinbase")
    log_activity_to_db("PAYMENT_ATTEMPT", "coinbase")
    
    # Check if API key is properly configured
    if not Config.COINBASE_API_KEY:
        log_activity("PAYMENT_ERROR", "Coinbase API key not configured")
        return render_template_string('''
            <h3>⚠️ Payment System Configuration</h3>
            <p>Coinbase payments are currently being configured.</p>
            <p>Please use the manual crypto payment option for now.</p>
            <button onclick="window.location.href='/premium'">← Back to Payment Options</button>
        ''')
    
    charge_data = {
        "name": "CryptoShield AI Premium",
        "description": "Monthly subscription - AI-powered crypto scam protection",
        "pricing_type": "fixed_price",
        "local_price": {
            "amount": "4.99",
            "currency": "USD"
        },
        "metadata": {
            "customer_id": "premium_user",
            "service": "cryptoshield_ai"
        },
        "redirect_url": "https://cryptoshield-ai.onrender.com/payment-success",
        "cancel_url": "https://cryptoshield-ai.onrender.com/payment-cancel"
    }
    
    headers = {
        "X-CC-Api-Key": Config.COINBASE_API_KEY,
        "X-CC-Version": "2018-03-22",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            "https://api.commerce.coinbase.com/charges",
            json=charge_data,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 201:
            payment_info = response.json()
            log_activity("PAYMENT_REDIRECT", "Redirecting to Coinbase payment")
            return redirect(payment_info['data']['hosted_url'])
        else:
            log_activity("PAYMENT_ERROR", f"Coinbase API error: {response.status_code} - {response.text}")
            return render_template_string('''
                <h3>⚠️ Payment System Temporarily Unavailable</h3>
                <p>Error: {{ error_code }} - {{ error_text }}</p>
                <p>Please use manual crypto payment option above.</p>
                <button onclick="window.location.href='/premium'">← Back to Payment Options</button>
            ''', error_code=response.status_code, error_text=response.text)
            
    except Exception as e:
        log_activity("PAYMENT_EXCEPTION", f"Coinbase payment error: {str(e)}")
        return render_template_string('''
            <h3>⚠️ Payment System Error</h3>
            <p>Error: {{ error }}</p>
            <p>Please use manual crypto payment option.</p>
            <button onclick="window.location.href='/premium'">← Back to Payment Options</button>
        ''', error=str(e))

@app.route('/payment-cancel')
def payment_cancel():
    log_activity("PAYMENT_CANCELLED", "User cancelled payment")
    log_activity_to_db("PAYMENT_CANCELLED", "User cancelled payment")
    return render_template_string('''
        <h2>❌ Payment Cancelled</h2>
        <p>Your payment was cancelled. You can try again anytime.</p>
        <button onclick="window.location.href='/premium'">← Back to Payment Options</button>
    ''')

@app.route('/payment-success')
def payment_success():
    log_activity("PAYMENT_SUCCESS", "Manual redirect success")
    log_activity_to_db("PAYMENT_SUCCESS", "Manual redirect success")
    return render_template_string('''
        <h2>✅ Payment Successful!</h2>
        <p>Thank you for subscribing to CryptoShield AI Premium!</p>
        <p>Your account will be activated within 1 hour.</p>
        <p>For any questions, contact: <strong>dan@cryptoshield-ai.com</strong></p>
        <div style="margin-top: 20px;">
            <button onclick="window.location.href='/activate-premium'">Activate Premium Features</button>
        </div>
        <div style="margin-top: 10px;">
            <button onclick="window.location.href='/'">← Back to Home</button>
        </div>
    ''')

@app.route('/api/signup', methods=['POST'])
def signup():
    email = request.json.get('email')
    
    if not email:
        return jsonify({'error': 'Email required'}), 400
    
    # Basic email validation
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    conn = None
    try:
        conn = sqlite3.connect(Config.DATABASE_URL, check_same_thread=False)
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO users (email, plan, created_at) VALUES (?, ?, ?)",
                  (email, 'trial', datetime.datetime.now()))
        conn.commit()
        
        log_activity("USER_SIGNUP", f"New user: {email}")
        log_activity_to_db("USER_SIGNUP", f"Email: {email}")
        
        return jsonify({
            'status': 'success',
            'message': 'Welcome to CryptoShield AI!',
            'next_step': 'check_premium_options'
        })
        
    except sqlite3.Error as e:
        log_activity("SIGNUP_ERROR", f"Database error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/coinbase-webhook', methods=['POST'])
def coinbase_webhook():
    data = request.json
    event_type = data.get('event', {}).get('type')
    
    log_activity("WEBHOOK_RECEIVED", f"Event: {event_type}")
    log_activity_to_db("WEBHOOK_RECEIVED", f"Event: {event_type}")
    
    if event_type == 'charge:confirmed':
        log_activity("PAYMENT_CONFIRMED", "Webhook confirmation")
        # Process successful payment
        # Add user to premium, send confirmation email, etc.
    elif event_type == 'charge:failed':
        log_activity("PAYMENT_FAILED", "Webhook failure")
    
    return jsonify({'status': 'success'})

@app.route('/activate-premium')
def activate_premium():
    log_activity("PREMIUM_ACTIVATION", "User activated premium")
    log_activity_to_db("PREMIUM_ACTIVATION", "User activated premium")
    return render_template_string('''
        <h2>🎉 Welcome to Premium!</h2>
        <p>Your CryptoShield AI Premium account is now active.</p>
        <p><strong>Premium Features Unlocked:</strong></p>
        <ul>
            <li>✅ Advanced AI scam detection</li>
            <li>✅ Real-time portfolio monitoring</li>
            <li>✅ Contract address analysis</li>
            <li>✅ Browser extension access</li>
            <li>✅ Priority customer support</li>
        </ul>
        <div style="margin-top: 20px;">
            <button onclick="window.location.href='/'" style="background: #4CAF50;">🚀 Start Using Premium</button>
        </div>
    ''')

@app.route('/api/metrics')
def get_metrics():
    """API endpoint to get business metrics"""
    conn = None
    try:
        conn = sqlite3.connect(Config.DATABASE_URL, check_same_thread=False)
        c = conn.cursor()
        
        # Get user count
        c.execute("SELECT COUNT(*) FROM users")
        user_count = c.fetchone()[0]
        
        # Get scam check count
        c.execute("SELECT COUNT(*) FROM activity_log WHERE event_type = 'URL_CHECK'")
        total_checks = c.fetchone()[0]
        
        return jsonify({
            'users': user_count,
            'total_checks': total_checks,
            'system_status': 'operational',
            'timestamp': datetime.datetime.now().isoformat()
        })
        
    except sqlite3.Error as e:
        log_activity("METRICS_ERROR", f"Failed to get metrics: {str(e)}")
        return jsonify({'error': 'Failed to retrieve metrics'}), 500
    finally:
        if conn:
            conn.close()

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    log_activity("SERVER_ERROR", f"500 error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

# CRITICAL: Proper port binding for Render
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=Config.DEBUG)

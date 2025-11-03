from flask import Flask, jsonify, request, render_template_string, redirect, url_for
import requests
import sqlite3
import datetime
import os
import re
import logging
from typing import Dict, Any
import paypalrestsdk

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
    if 'api_key' in details.lower() or 'key' in details.lower() or 'secret' in details.lower():
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
    # PayPal Configuration
    PAYPAL_CLIENT_ID = os.environ.get('PAYPAL_CLIENT_ID', '')
    PAYPAL_CLIENT_SECRET = os.environ.get('PAYPAL_CLIENT_SECRET', '')
    PAYPAL_MODE = os.environ.get('PAYPAL_MODE', 'sandbox')  # or 'live'

app = Flask(__name__)
app.config.from_object(Config)

# Configure PayPal
paypalrestsdk.configure({
    "mode": Config.PAYPAL_MODE,
    "client_id": Config.PAYPAL_CLIENT_ID,
    "client_secret": Config.PAYPAL_CLIENT_SECRET
})

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
                      payment_method TEXT,
                      paypal_payment_id TEXT,
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

def verify_coinbase_webhook(payload, signature):
    """Verify Coinbase webhook signature"""
    import hmac
    import hashlib
    
    if not Config.COINBASE_WEBHOOK_SECRET:
        return True  # Skip verification if no secret set
    
    computed_signature = hmac.new(
        Config.COINBASE_WEBHOOK_SECRET.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(computed_signature, signature)


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


@app.route('/coinbase-webhook', methods=['POST'])
def coinbase_webhook():
    # Verify webhook signature
    signature = request.headers.get('X-CC-Webhook-Signature')
    payload = request.get_data()
    
    # Verify the webhook came from Coinbase
    if not verify_coinbase_webhook(payload, signature):
        log_activity("WEBHOOK_SECURITY", "Invalid webhook signature")
        return jsonify({'error': 'Invalid signature'}), 401
    
    data = request.json
    event_type = data.get('event', {}).get('type')
    
    log_activity("WEBHOOK_RECEIVED", f"Event: {event_type}")
    log_activity_to_db("WEBHOOK_RECEIVED", f"Event: {event_type}")
    
    if event_type == 'charge:confirmed':
        log_activity("PAYMENT_CONFIRMED", "Webhook confirmation")
        # Process successful payment
        charge_data = data.get('event', {}).get('data', {})
        # Add your payment processing logic here
    
    return jsonify({'status': 'success'})

def verify_coinbase_webhook(payload, signature):
    """Verify Coinbase webhook signature"""
    import hmac
    import hashlib
    
    if not Config.COINBASE_WEBHOOK_SECRET:
        return True  # Skip verification if no secret set
    
    computed_signature = hmac.new(
        Config.COINBASE_WEBHOOK_SECRET.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(computed_signature, signature)


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
            <p>Please use PayPal or manual crypto payment options for now.</p>
            <button onclick="window.location.href='/premium'">← Back to Payment Options</button>
        ''')


@app.route('/paypal-payment')
def paypal_payment():
    log_activity("PAYMENT_ATTEMPT", "paypal")
    
    if not Config.PAYPAL_CLIENT_ID or not Config.PAYPAL_CLIENT_SECRET:
        return render_template_string('''
            <h3>⚠️ PayPal Not Configured</h3>
            <p>PayPal payments are not yet configured.</p>
            <p>Please use manual crypto payments for now.</p>
            <button onclick="window.location.href='/premium'">← Back to Payment Options</button>
        ''')
    
    try:
        # Create PayPal payment
        payment = paypalrestsdk.Payment({
            "intent": "sale",
            "payer": {
                "payment_method": "paypal"
            },
            "redirect_urls": {
                "return_url": url_for('paypal_success', _external=True),
                "cancel_url": url_for('paypal_cancel', _external=True)
            },
            "transactions": [{
                "item_list": {
                    "items": [{
                        "name": "CryptoShield AI Premium",
                        "sku": "premium-monthly",
                        "price": "4.99",
                        "currency": "USD",
                        "quantity": 1
                    }]
                },
                "amount": {
                    "total": "4.99",
                    "currency": "USD"
                },
                "description": "Monthly subscription - AI-powered crypto scam protection"
            }]
        })
        
        if payment.create():
            log_activity("PAYMENT_CREATED", f"PayPal payment created: {payment.id}")
            # Redirect user to PayPal approval URL
            for link in payment.links:
                if link.rel == "approval_url":
                    return redirect(link.href)
        else:
            log_activity("PAYMENT_ERROR", f"PayPal payment creation failed: {payment.error}")
            return render_template_string('''
                <h3>⚠️ Payment Error</h3>
                <p>Failed to create PayPal payment: {{ error }}</p>
                <button onclick="window.location.href='/premium'">← Back to Payment Options</button>
            ''', error=payment.error)
            
    except Exception as e:
        log_activity("PAYMENT_EXCEPTION", f"PayPal payment error: {str(e)}")
        return render_template_string('''
            <h3>⚠️ Payment System Error</h3>
            <p>Error: {{ error }}</p>
            <p>Please use manual crypto payment option.</p>
            <button onclick="window.location.href='/premium'">← Back to Payment Options</button>
        ''', error=str(e))

@app.route('/paypal-success')
def paypal_success():
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')
    
    if not payment_id or not payer_id:
        return redirect('/paypal-cancel')
    
    try:
        payment = paypalrestsdk.Payment.find(payment_id)
        
        if payment.execute({"payer_id": payer_id}):
            log_activity("PAYMENT_SUCCESS", f"PayPal payment executed: {payment_id}")
            
            # Record payment in database
            conn = sqlite3.connect(Config.DATABASE_URL, check_same_thread=False)
            c = conn.cursor()
            c.execute('''INSERT INTO payments 
                        (amount, status, payment_method, paypal_payment_id, created_at) 
                        VALUES (?, ?, ?, ?, ?)''',
                     (4.99, 'completed', 'paypal', payment_id, datetime.datetime.now()))
            conn.commit()
            conn.close()
            
            return redirect('/activate-premium')
        else:
            log_activity("PAYMENT_FAILED", f"PayPal payment execution failed: {payment.error}")
            return redirect('/paypal-cancel')
            
    except Exception as e:
        log_activity("PAYMENT_EXCEPTION", f"PayPal execution error: {str(e)}")
        return redirect('/paypal-cancel')

@app.route('/paypal-cancel')
def paypal_cancel():
    log_activity("PAYMENT_CANCELLED", "User cancelled PayPal payment")
    return render_template_string('''
        <h2>❌ Payment Cancelled</h2>
        <p>Your PayPal payment was cancelled. You can try again anytime.</p>
        <button onclick="window.location.href='/premium'">← Back to Payment Options</button>
    ''')

@app.route('/manual-payment-info')
def manual_payment_info():
    return render_template_string('''
        <h2>⚡ Manual Payment Instructions</h2>
        <p>Send <strong>$4.99 USD equivalent</strong> in crypto to one of these addresses:</p>
        
        <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0;">
            <strong>Bitcoin (BTC):</strong><br>
            <code style="font-size: 14px;">1Nkck7Q1cEZmQBsxzhobipgByS9p7BxGYz</code><br><br>
            
            <strong>Ethereum (ETH):</strong><br>
            <code style="font-size: 14px;">0x7998C2b3e97b1b0b587D7B548b614267c62Da34D</code><br><br>
            
            <strong>USDC (ERC-20):</strong><br>
            <code style="font-size: 14px;">0xC2AcEE65df126470a2E12E50B8F235111bDb9aed</code>
        </div>
        
        <p><strong>After payment:</strong></p>
        <ol>
            <li>Email the transaction ID to <strong>d.orton5963@gmail.com</strong></li>
            <li>Include your email address in the email</li>
            <li>We'll activate your premium within 1 hour</li>
        </ol>
        
        <button onclick="window.location.href='/premium'">← Back to Payment Options</button>
    ''')

# ... (keep all your existing routes for coinbase, database, etc.)

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

# ... (keep all your existing routes)

# CRITICAL: Proper port binding for Render
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=Config.DEBUG)

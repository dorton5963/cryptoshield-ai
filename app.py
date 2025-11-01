from flask import Flask, jsonify, request, render_template_string
import requests
import sqlite3
import datetime
import os

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False)

@app.route('/coinbase-payment')
def coinbase_payment():
    # Your Coinbase Commerce API Key
    api_key = "7bce8152-0224-4970-a5de-267bd06a2e34"  # Replace with actual key
    
    charge_data = {
        "name": "CryptoShield AI Premium",
        "description": "Monthly subscription - AI scam protection",
        "pricing_type": "fixed_price",
        "local_price": {
            "amount": "4.99",
            "currency": "USD"
        },
        "metadata": {
            "customer_name": "premium_user"
        }
    }
    
    headers = {
        "X-CC-Api-Key": api_key,
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
            return redirect(payment_info['data']['hosted_url'])
        else:
            return f"Payment system error: {response.status_code}"
            
    except Exception as e:
        return f"Payment temporarily unavailable: {str(e)}"


app = Flask(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect('cryptoshield.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, email TEXT, plan TEXT, created_at TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS payments
                 (id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, status TEXT)''')
    conn.commit()
    conn.close()

init_db()

# Enhanced scam database
SCAM_BLACKLIST = [
    'fakewallet.com', 'phishing-site.com', 'free-crypto-giveaway.com',
    'metamask-phishing.com', 'wallet-connect-scam.com', 'airdrop-scam.net'
]

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CryptoShield AI - Protect Your Crypto</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .alert { background: #ffebee; color: #c62828; padding: 15px; border-radius: 5px; }
        .safe { background: #e8f5e8; color: #2e7d32; padding: 15px; border-radius: 5px; }
        .premium { background: #fff3e0; border: 2px solid #ff9800; padding: 20px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>🛡️ CryptoShield AI</h1>
    <p><strong>Status:</strong> ACTIVE | <strong>Revenue Target:</strong> $100k/month</p>
    
    <div class="premium">
        <h3>🚀 PREMIUM PROTECTION - $4.99/month</h3>
        <p>Real-time AI scam detection • Contract analysis • Portfolio monitoring</p>
        <button onclick="signup()">Start 7-Day Free Trial</button>
    </div>

    <h2>Test URL Protection</h2>
    <input type="text" id="urlInput" placeholder="Enter URL to check" style="width: 300px; padding: 8px;">
    <button onclick="checkUrl()">Check Safety</button>
    <div id="result"></div>

    <script>
        async function checkUrl() {
            const url = document.getElementById('urlInput').value;
            const response = await fetch(`/api/check?url=${encodeURIComponent(url)}`);
            const data = await response.json();
            
            const resultDiv = document.getElementById('result');
            if (data.safe) {
                resultDiv.innerHTML = `<div class="safe">✅ SAFE: ${data.message}</div>`;
            } else {
                resultDiv.innerHTML = `<div class="alert">🚨 BLOCKED: ${data.message}</div>`;
            }
        }
        
        function signup() {
            alert('Premium activation starting... Payment integration in progress.');
            // Stripe integration next
        }
    </script>
</body>
</html>
"""
@app.route('/premium')
def premium():
    return """
    <h3>🚀 CryptoShield AI Premium - $4.99/month</h3>
    <p>Choose payment method:</p>
    <a href="/coinbase-payment" style="background: #0052FF; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px;">
        Pay with Coinbase (Crypto)
    </a>
    <p><em>Instant setup - Your existing Coinbase account works</em></p>
    """

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/check')
def check_url():
    url = request.args.get('url', '')
    
    # Basic scam detection
    is_scam = any(domain in url.lower() for domain in SCAM_BLACKLIST)
    
    # Log the check (for analytics)
    print(f"URL Check: {url} - {'BLOCKED' if is_scam else 'ALLOWED'}")
    
    return jsonify({
        'url': url,
        'safe': not is_scam,
        'risk_level': 'HIGH' if is_scam else 'LOW',
        'message': 'Known scam site detected' if is_scam else 'URL appears safe',
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/api/signup', methods=['POST'])
def signup():
    # Basic user registration
    email = request.json.get('email')
    
    conn = sqlite3.connect('cryptoshield.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (email, plan, created_at) VALUES (?, ?, ?)",
              (email, 'trial', datetime.datetime.now()))
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'success',
        'message': '7-day trial started',
        'next_step': 'payment_integration'
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
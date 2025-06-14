from flask import Flask, render_template, jsonify
import requests
import os

app = Flask(__name__, static_url_path='/static', static_folder='static', template_folder='templates')

# Supported coins with metadata
COINS = {
    "bitcoin": {"name": "Bitcoin (BTC)", "logo": "btc.png"},
    "ethereum": {"name": "Ethereum (ETH)", "logo": "eth.png"},
    "usdt": {"name": "Tether (USDT)", "logo": "usdt.png"},
    "usdc": {"name": "USD Coin (USDC)", "logo": "usdc.png"}
}

@app.route("/")
def index():
    try:
        url = "https://api.coingecko.com/api/v3/simple/price"
        params = {
            "ids": ','.join(COINS.keys()),
            "vs_currencies": "usd"
        }
        response = requests.get(url, params=params)
        prices = response.json()

        coins_data = []
        for key, meta in COINS.items():
            coin_price = prices.get(key, {}).get("usd", 0)
            coins_data.append({
                "symbol": key.upper(),
                "name": meta["name"],
                "price": f"${coin_price:,.2f}",
                "logo": f"/static/{meta['logo']}"
            })

        return render_template("index.html", coins=coins_data)

    except Exception as e:
        return jsonify({"error": f"Failed to load data: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True)

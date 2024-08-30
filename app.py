from flask import Flask, request, redirect, render_template, jsonify
import requests
import hmac
import hashlib

app = Flask(__name__)

API_KEY = "cad8562e309056451cfabd7ec0db475f"
API_SECRET = "5b482566f1284d8e9fe8a5b4907dfd8d"
REDIRECT_URI = "https://5ff1022c.r15.cpolar.top/auth/callback"
SCOPES = "read_script_tags,write_script_tags"

access_token = None
shop_url = "harvey-teststore.myshopify.com"
resources = []
js_injection_enabled = True

@app.route('/auth')
def auth():
    shop = request.args.get('shop')
    if not shop:
        return "Missing shop parameter", 400

    global shop_url
    shop_url = shop

    state = "unique_nonce_value"

    auth_url = (
        f"https://{shop}/admin/oauth/authorize?"
        f"client_id={API_KEY}&scope={SCOPES}&redirect_uri={REDIRECT_URI}&state={state}"
    )

    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    global access_token

    shop = request.args.get('shop')
    code = request.args.get('code')
    hmac_param = request.args.get('hmac')
    state = request.args.get('state')

    if not (shop and code and hmac_param and state):
        return "Missing parameters", 400

    if not validate_hmac(request.args, API_SECRET):
        return "Invalid HMAC validation", 403

    try:
        access_token = get_access_token(shop, code)
        if access_token:
            update_script_tags(shop)
    except Exception as e:
        return f"Failed to get access token: {e}", 500

    return redirect('/')

@app.route('/')
def home():
    if not access_token:
        return (
            "<h1>Welcome to your Shopify App</h1>"
            "<p>Please <a href='/auth?shop=harvey-teststore.myshopify.com'>authorize the app</a> to continue.</p>"
        )

    return render_template('admin.html', resources=resources, js_injection_enabled=js_injection_enabled)

@app.route('/add_resource', methods=['POST'])
def add_resource():
    global resources
    resource_type = request.form.get('resource_type')
    resource_content = request.form.get('resource_content')

    if resource_type not in ['js', 'css']:
        return "Invalid resource type", 400

    resource_id = len(resources) + 1
    resources.append({"id": resource_id, "type": resource_type, "content": resource_content})
    if access_token and shop_url:
        update_script_tags(shop_url)
    return redirect('/')

@app.route('/remove_resource', methods=['POST'])
def remove_resource():
    global resources
    resource_id = int(request.form.get('resource_id'))

    resources = [res for res in resources if res['id'] != resource_id]
    if access_token and shop_url:
        update_script_tags(shop_url)
    return redirect('/')

@app.route('/toggle_js', methods=['POST'])
def toggle_js():
    global js_injection_enabled
    js_injection_enabled = not js_injection_enabled
    return redirect('/')

def get_access_token(shop, code):
    url = f"https://{shop}/admin/oauth/access_token"
    payload = {
        "client_id": API_KEY,
        "client_secret": API_SECRET,
        "code": code
    }
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()

    data = response.json()
    return data.get("access_token")

def validate_hmac(query_params, secret):
    hmac_param = query_params.get('hmac')
    if not hmac_param:
        return False

    sorted_keys = sorted(k for k in query_params if k != 'hmac')
    message = '&'.join(f"{k}={query_params[k]}" for k in sorted_keys)
    
    expected_hmac = hmac.new(
        key=secret.encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac_param == expected_hmac

def update_script_tags(shop):
    url = f"https://{shop}/admin/api/2024-07/script_tags.json"
    headers = {"X-Shopify-Access-Token": access_token, "Content-Type": "application/json"}

    # 获取现有的 script_tags
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    existing_script_tags = response.json().get("script_tags", [])
    existing_urls = {tag["src"] for tag in existing_script_tags}

    # 插入或更新 JavaScript 代码
    if js_injection_enabled:
        for resource in resources:
            if resource["type"] == "js":
                script_tag = {
                    "script_tag": {
                        "event": "onload",
                        "src": resource["content"]
                    }
                }
                if script_tag["script_tag"]["src"] not in existing_urls:
                    response = requests.post(url, json=script_tag, headers=headers)
                    if response.status_code == 422:
                        print(f"Failed to create script tag: {response.json()}")
                    response.raise_for_status()
                    existing_urls.add(script_tag["script_tag"]["src"])
    else:
        # 删除现有的 JavaScript 标签
        for tag in existing_script_tags:
            if tag["src"].startswith("http"):
                response = requests.delete(f"{url}/{tag['id']}.json", headers=headers)
                response.raise_for_status()


if __name__ == "__main__":
    app.run(port=8080)

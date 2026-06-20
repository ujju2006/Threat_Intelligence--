import json
import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from modules.analyzer import ThreatAnalyzer

app = Flask(__name__)
analyzer = ThreatAnalyzer()
app.secret_key = "super_secret_threatfusion_key"

# Helper to load JSON data
def load_json(filename):
    filepath = os.path.join(os.path.dirname(__file__), 'data', filename)
    with open(filepath, 'r') as f:
        return json.load(f)

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        users = load_json('users.json')
        for user in users:
            # Using simple auth for demo (checking cleartext_demo_password)
            if user['username'] == username and user['cleartext_demo_password'] == password:
                session['user'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('dashboard'))
        return render_template('login.html', error="Invalid Credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: return redirect(url_for('login'))
    
    # Calculate some dashboard stats
    iocs = load_json('iocs.json')
    cves = load_json('cves.json')
    critical_threats = sum(1 for i in iocs if i.get('severity') == 'CRITICAL')
    
    return render_template('dashboard.html', 
                           role=session.get('role'),
                           total_iocs=len(iocs),
                           total_cves=len(cves),
                           critical_threats=critical_threats)

@app.route('/api/search')
def api_search():
    query = request.args.get('q', '').lower()
    results = []
    
    if not query:
        return jsonify(results)
        
    iocs = load_json('iocs.json')
    cves = load_json('cves.json')
    
    for ioc in iocs:
        if query in ioc['value'].lower() or query in ioc['ioc_id'].lower():
            results.append({"type": "IOC", "id": ioc['ioc_id'], "value": ioc['value'], "severity": ioc['severity']})
            
    for cve in cves:
        if query in cve['cve_id'].lower() or query in cve['description'].lower():
            results.append({"type": "CVE", "id": cve['cve_id'], "value": cve['description'][:50] + "...", "severity": cve['severity']})
            
    return jsonify(results)

@app.route('/ioc_correlation')
def ioc_correlation():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('ioc_graph.html', role=session.get('role'))

@app.route('/ip_analysis')
def ip_analysis():
    if 'user' not in session: return redirect(url_for('login'))
    ip = request.args.get('ip', '')
    return render_template('ip_analysis.html', role=session.get('role'), search_ip=ip)

@app.route('/url_analysis')
def url_analysis():
    if 'user' not in session: return redirect(url_for('login'))
    url = request.args.get('url', '')
    results = None
    if url:
        results = analyzer.analyze_url(url)
    return render_template('url_analysis.html', role=session.get('role'), search_url=url, results=results)

@app.route('/cve_intelligence')
def cve_intelligence():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('cve_lookup.html', role=session.get('role'))

@app.route('/exports')
def exports():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('exports.html', role=session.get('role'))

@app.route('/api/iocs')
def api_iocs():
    return jsonify(load_json('iocs.json'))

@app.route('/api/cves')
def api_cves():
    return jsonify(load_json('cves.json'))

@app.route('/api/mitre')
def api_mitre():
    return jsonify(load_json('mitre.json'))

if __name__ == '__main__':
    # Force debug mode off in production, but on for development
    app.run(debug=True, host='0.0.0.0', port=5001)

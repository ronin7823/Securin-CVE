from flask import Flask, request, jsonify, render_template
from database_setup import db, CVE, init_db
import requests
import os

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cves.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
init_db(app)

API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Fetch CVE data from NVD API
@app.route('/sync', methods=['GET'])
def sync_cves():
    start_index = 0
    results_per_page = 100
    total_results = 0

    while True:
        response = requests.get(f"{API_BASE_URL}?startIndex={start_index}&resultsPerPage={results_per_page}")
        data = response.json()
        cve_items = data.get('vulnerabilities', [])
        
        for item in cve_items:
            cve_id = item['cve']['id']
            description = item['cve']['descriptions'][0]['value']
            published_date = item['cve']['published']
            last_modified_date = item['cve']['lastModified']
            metrics = item['cve'].get('metrics', {})
            base_score = None
            vector_string = None
            
            if 'cvssMetricV3' in metrics:
                base_score = metrics['cvssMetricV3'][0]['cvssData']['baseScore']
                vector_string = metrics['cvssMetricV3'][0]['cvssData']['vectorString']

            # Avoid duplicates
            existing_cve = CVE.query.filter_by(cve_id=cve_id).first()
            if not existing_cve:
                new_cve = CVE(
                    cve_id=cve_id,
                    description=description,
                    published_date=published_date,
                    last_modified_date=last_modified_date,
                    base_score=base_score,
                    vector_string=vector_string
                )
                db.session.add(new_cve)

        db.session.commit()

        total_results += len(cve_items)
        if len(cve_items) < results_per_page:
            break
        start_index += results_per_page

    return jsonify({'message': f'{total_results} CVEs synchronized successfully!'})

# Get CVEs based on filters
@app.route('/cves', methods=['GET'])
def get_cves():
    cve_id = request.args.get('cve_id')
    year = request.args.get('year')
    score = request.args.get('score')
    days = request.args.get('days')

    query = CVE.query

    if cve_id:
        query = query.filter(CVE.cve_id == cve_id)
    if year:
        query = query.filter(CVE.published_date.startswith(year))
    if score:
        query = query.filter(CVE.base_score >= float(score))
    if days:
        from datetime import datetime, timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=int(days))
        query = query.filter(CVE.last_modified_date >= cutoff_date.strftime('%Y-%m-%d'))

    results = query.all()
    return jsonify([{
        'cve_id': cve.cve_id,
        'description': cve.description,
        'published_date': cve.published_date,
        'last_modified_date': cve.last_modified_date,
        'base_score': cve.base_score,
        'vector_string': cve.vector_string
    } for cve in results])

@app.route('/cves/<cve_id>', methods=['GET'])
def get_cve_details(cve_id):
    cve = CVE.query.filter_by(cve_id=cve_id).first()
    if not cve:
        return jsonify({'error': 'CVE not found'}), 404

    return jsonify({
        'cve_id': cve.cve_id,
        'description': cve.description,
        'published_date': cve.published_date,
        'last_modified_date': cve.last_modified_date,
        'base_score': cve.base_score,
        'vector_string': cve.vector_string
    })

@app.route('/cves/list')
def list_cves():
    return render_template('list.html')

@app.route('/cves/details/<cve_id>')
def details(cve_id):
    return render_template('details.html', cve_id=cve_id)

if __name__ == '__main__':
    app.run(debug=True)


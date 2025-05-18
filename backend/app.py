from flask import Flask, request, jsonify
from flask_cors import CORS
from detection import predict_phishing, predict_message, analyze_message_with_links, extract_urls, analyze_image,normalize_url
import re
import os
import pytesseract
from PIL import Image
import io

app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return "📡 Fake Link & Message Detection API is running."

@app.route('/predict/link', methods=['POST'])
def predict_link():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing "url" in request body'}), 400
        
        url = data['url']
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
            
        result = predict_phishing(url)
        return jsonify({
            'url': url,
            'prediction': result.get('prediction', 'Unknown'),
            'reason': result.get('reason', 'No details available'),
            'is_safe': result.get('prediction', '').lower() == 'legitimate'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'prediction': 'Error',
            'reason': 'An error occurred during analysis'
        }), 500

@app.route('/predict/message', methods=['POST'])
def predict_text():
    try:
        data = request.get_json()
        message = data.get('message', '')
        
        if not message:
            return jsonify({'error': 'Message cannot be empty'}), 400

        urls = extract_urls(message)
        message_without_urls = re.sub(r'http[s]?://\S+', '', message)
        message_prediction = predict_message(message_without_urls)

        url_results = []
        phishing_detected = False
        
        for url in urls:
            url=normalize_url(url)
            phishing_response = predict_phishing(url)
            url_results.append({
                'url': url,
                'result': phishing_response,
                'is_phishing': phishing_response.get("prediction", "").lower() in ["phishing", "suspicious"]
            })
            if url_results[-1]['is_phishing']:
                phishing_detected = True

        if phishing_detected:
            message_prediction = "spam"

        return jsonify({
            "message_prediction": message_prediction,
            "urls_detected": url_results,
            "original_message": message,
            "contains_unsafe_links": phishing_detected
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message_prediction': 'Error'
        }), 500

@app.route('/upload/image', methods=['POST'])
def upload_image():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        temp_path = os.path.join('/tmp', file.filename)
        file.save(temp_path)
        
        # Analyze the image
        analysis_result = analyze_image(temp_path)
        os.remove(temp_path)
        
        # Check if any link is phishing
        phishing_detected = False
        links = []
        
        if 'urls_detected' in analysis_result:
            for url_info in analysis_result['urls_detected']:
                is_phishing = url_info.get('result', {}).get('prediction', '').lower() in ['phishing', 'suspicious']
                links.append({
                    'url': url_info.get('url', ''),
                    'is_phishing': is_phishing
                })
                if is_phishing:
                    phishing_detected = True
        
        # If any phishing link found, mark as spam regardless of text content
        message_prediction = analysis_result.get('message_prediction', '').lower()
        if phishing_detected:
            message_prediction = 'spam'

        response = {
            'extracted_text': analysis_result.get('extracted_text', ''),
            'message': analysis_result.get('cleaned_message', ''),
            'spam': message_prediction in ['spam', 'phishing'],
            'links': links,
            'contains_unsafe_links': phishing_detected
        }
        
        return jsonify(response)
    
    except Exception as e:
        print(f"[ERROR] {e}")
        return jsonify({'error': str(e)}), 500
if __name__ == '__main__':
    app.run(debug=True)
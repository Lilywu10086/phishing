from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
import numpy as np
import pickle
from datetime import datetime
from feature import FeatureExtraction
from models import db, DetectionHistory

# Load model
with open("pickle/model.pkl", "rb") as file:
    gbc = pickle.load(file)

api = Blueprint('api', __name__)

@api.route('/detect', methods=['POST'])
def detect_single():
    """Single URL detection API"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Please provide URL parameter'}), 400
        
        url = data['url']
        
        # Feature extraction
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)
        
        # Prediction
        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
        
        result = {
            'url': url,
            'is_safe': y_pro_non_phishing >= 0.5,
            'confidence_score': float(y_pro_non_phishing),
            'detected_at': datetime.utcnow().isoformat()
        }
        
        # Save detection history if user is logged in
        if current_user.is_authenticated:
            detection = DetectionHistory(
                user_id=current_user.id,
                url=url,
                is_safe=result['is_safe'],
                confidence_score=result['confidence_score']
            )
            db.session.add(detection)
            db.session.commit()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'Detection failed: {str(e)}'}), 500

@api.route('/batch_detect', methods=['POST'])
def detect_batch():
    """Batch URL detection API"""
    try:
        data = request.get_json()
        if not data or 'urls' not in data:
            return jsonify({'error': 'Please provide urls parameter'}), 400
        
        urls = data['urls']
        if not isinstance(urls, list):
            return jsonify({'error': 'urls must be an array format'}), 400
        
        if len(urls) > 50:
            return jsonify({'error': 'Maximum 50 URLs can be detected at once'}), 400
        
        results = []
        
        for url in urls:
            try:
                # Feature extraction
                obj = FeatureExtraction(url)
                x = np.array(obj.getFeaturesList()).reshape(1, 30)
                
                # Prediction
                y_pred = gbc.predict(x)[0]
                y_pro_phishing = gbc.predict_proba(x)[0, 0]
                y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
                
                result = {
                    'url': url,
                    'is_safe': y_pro_non_phishing >= 0.5,
                    'confidence_score': float(y_pro_non_phishing),
                    'detected_at': datetime.utcnow().isoformat()
                }
                
                # Save detection history if user is logged in
                if current_user.is_authenticated:
                    detection = DetectionHistory(
                        user_id=current_user.id,
                        url=url,
                        is_safe=result['is_safe'],
                        confidence_score=result['confidence_score']
                    )
                    db.session.add(detection)
                
                results.append(result)
                
            except Exception as e:
                result = {
                    'url': url,
                    'is_safe': False,
                    'confidence_score': 0.0,
                    'detected_at': datetime.utcnow().isoformat(),
                    'error': str(e)
                }
                results.append(result)
        
        # Commit all detection history
        if current_user.is_authenticated:
            db.session.commit()
        
        return jsonify({
            'total': len(results),
            'safe_count': len([r for r in results if r.get('is_safe', False)]),
            'unsafe_count': len([r for r in results if not r.get('is_safe', True)]),
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': f'Batch detection failed: {str(e)}'}), 500

@api.route('/history', methods=['GET'])
@login_required
def get_history():
    """Get user detection history API"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Get user's detection history
        detections = DetectionHistory.query.filter_by(user_id=current_user.id)\
            .order_by(DetectionHistory.detected_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        history = []
        for detection in detections.items:
            history.append({
                'id': detection.id,
                'url': detection.url,
                'is_safe': detection.is_safe,
                'confidence_score': float(detection.confidence_score),
                'detected_at': detection.detected_at.isoformat()
            })
        
        return jsonify({
            'history': history,
            'total': detections.total,
            'pages': detections.pages,
            'current_page': page,
            'per_page': per_page
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get history: {str(e)}'}), 500

@api.route('/stats', methods=['GET'])
@login_required
def get_stats():
    """Get user statistics API"""
    try:
        # Calculate statistics
        total_detections = DetectionHistory.query.filter_by(user_id=current_user.id).count()
        safe_count = DetectionHistory.query.filter_by(user_id=current_user.id, is_safe=True).count()
        unsafe_count = DetectionHistory.query.filter_by(user_id=current_user.id, is_safe=False).count()
        
        # Calculate average confidence
        avg_confidence = db.session.query(db.func.avg(DetectionHistory.confidence_score))\
            .filter_by(user_id=current_user.id).scalar() or 0.0
        
        return jsonify({
            'total_detections': total_detections,
            'safe_count': safe_count,
            'unsafe_count': unsafe_count,
            'avg_confidence': float(avg_confidence),
            'safe_percentage': (safe_count / total_detections * 100) if total_detections > 0 else 0
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get statistics: {str(e)}'}), 500 
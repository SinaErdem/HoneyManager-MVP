import os
import logging
from flask import Flask, request, jsonify
from models import db, Alert

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    
    # 12-Factor: Load config from environment
    database_url = os.environ.get('DATABASE_URL')
    
    if not database_url:
        logger.warning("DATABASE_URL environment variable is not set!")
        # Fallback to in-memory sqlite if no config provided (useful for quick local test without DB)
        database_url = "sqlite:///:memory:"

    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    # Healthcheck endpoint (Important for AWS ECS / App Runner)
    @app.route('/api/health', methods=['GET'])
    def health_check():
        try:
            # Check DB connection
            db.session.execute(db.text('SELECT 1'))
            return jsonify({'status': 'healthy', 'database': 'connected'}), 200
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({'status': 'unhealthy', 'database': 'disconnected', 'error': str(e)}), 503

    # Log ingestion endpoint
    @app.route('/api/logs', methods=['POST'])
    def receive_log():
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No JSON payload provided'}), 400

        # Basic validation
        required_fields = ['severity', 'honeypot_name', 'source_ip', 'event_type']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400

        try:
            new_alert = Alert(
                severity=data['severity'],
                honeypot_name=data['honeypot_name'],
                honeypot_type=data.get('honeypot_type'),
                source_ip=data['source_ip'],
                event_type=data['event_type'],
                description=data.get('description'),
                raw_data=data.get('raw_data')
            )
            
            db.session.add(new_alert)
            db.session.commit()
            
            logger.info(f"Received new log from {data['source_ip']} - {data['event_type']}")
            return jsonify({'success': True, 'alert_id': new_alert.id}), 201

        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to process log: {e}")
            return jsonify({'success': False, 'error': 'Database error'}), 500
            
    # Simple GET endpoint to verify logs are saved
    @app.route('/api/logs', methods=['GET'])
    def get_logs():
        try:
            limit = request.args.get('limit', 10, type=int)
            alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
            return jsonify({'success': True, 'logs': [alert.to_dict() for alert in alerts]}), 200
        except Exception as e:
            return jsonify({'success': False, 'error': 'Database error'}), 500

    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

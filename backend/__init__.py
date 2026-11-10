# Backend package initialization
from backend.database import init_db
from backend.classifier import analyze_message_content
from backend.routes import api_bp

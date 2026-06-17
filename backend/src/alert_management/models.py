"""
Database models for alert management.

This module defines the SQLAlchemy models for storing alerts in the SQLite database.
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

Base = declarative_base()

class Alert(Base):
    """Alert model for storing detection results."""
    
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    alert_id = Column(String(64), unique=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    attack_type = Column(String(50), nullable=False)
    source_ip = Column(String(45))
    dest_ip = Column(String(45))
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String(10))
    message = Column(Text)
    explanation = Column(Text)
    ml_confidence = Column(Float)
    rule_id = Column(String(50))
    count_occurrences = Column(Integer, default=1)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default='active')  # active, resolved, false_positive
    
    def to_dict(self):
        """Convert alert to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'severity': self.severity,
            'attack_type': self.attack_type,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'source_port': self.source_port,
            'dest_port': self.dest_port,
            'protocol': self.protocol,
            'message': self.message,
            'explanation': self.explanation,
            'ml_confidence': self.ml_confidence,
            'rule_id': self.rule_id,
            'count_occurrences': self.count_occurrences,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'status': self.status
        }

def init_database(db_path='data/alerts.db'):
    """Initialize the database with tables."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    engine = create_engine(f'sqlite:///{db_path}', echo=False)
    Base.metadata.create_all(engine)
    return engine

def get_session(db_path='data/alerts.db'):
    """Get a database session."""
    engine = init_database(db_path)
    Session = sessionmaker(bind=engine)
    return Session()
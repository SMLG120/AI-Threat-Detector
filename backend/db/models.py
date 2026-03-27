from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
from core.database import Base


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    # HTTP fields
    ip_address = Column(String(45), index=True)
    method = Column(String(10))
    url = Column(Text)
    path = Column(Text)
    query_string = Column(Text)
    user_agent = Column(Text)
    referer = Column(Text)
    status_code = Column(Integer)
    response_size = Column(Integer)
    request_body = Column(Text)
    headers = Column(JSON)

    # Detection results
    threat_score = Column(Float, default=0.0, index=True)
    threat_level = Column(String(10), default="LOW")  # LOW / MEDIUM / HIGH
    is_malicious = Column(Boolean, default=False)
    attack_types = Column(JSON)  # list of detected attack categories

    # Model scores
    rule_score = Column(Float, default=0.0)
    isolation_forest_score = Column(Float, default=0.0)
    random_forest_score = Column(Float, default=0.0)
    autoencoder_score = Column(Float, default=0.0)

    # Features used
    features = Column(JSON)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    log_id = Column(UUID(as_uuid=True), nullable=False)
    ip_address = Column(String(45))
    threat_level = Column(String(10))
    threat_score = Column(Float)
    attack_types = Column(JSON)
    message = Column(Text)
    acknowledged = Column(Boolean, default=False)


class ModelMetadata(Base):
    __tablename__ = "model_metadata"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    model_name = Column(String(100))
    version = Column(String(20))
    trained_at = Column(DateTime(timezone=True))
    accuracy = Column(Float)
    samples_used = Column(Integer)
    is_active = Column(Boolean, default=True)
    model_metadata = Column(JSON, nullable=True)


from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, LargeBinary
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .session import Base

class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=func.now())
    
    assets = relationship("Asset", back_populates="target", cascade="all, delete-orphan")

class SourceFile(Base):
    __tablename__ = "source_files"
    # SMART: SHA256 Hash is the Primary Key. 
    # This automatically deduplicates identical files across different scans.
    hash = Column(String(64), primary_key=True, index=True)
    
    # SMART: Store as compressed binary (zlib) to save 80-90% storage space.
    content_compressed = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=func.now())

class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    url = Column(String, index=True)
    
    # SMART: Link to the SourceFile hash instead of a local file path
    source_hash = Column(String(64), ForeignKey("source_files.hash"), nullable=True)
    
    target = relationship("Target", back_populates="assets")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")
    
    # Access the source content via this relationship
    source_file = relationship("SourceFile")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    type = Column(String, index=True)
    severity = Column(String, index=True)
    evidence = Column(Text)
    line = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=func.now())
    
    asset = relationship("Asset", back_populates="findings")
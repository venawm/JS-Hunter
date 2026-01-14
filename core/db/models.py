from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship, declarative_base
Base = declarative_base()
class Target(Base):
 __tablename__ = 'targets'; id = Column(Integer, primary_key=True); domain = Column(String, unique=True); assets = relationship('Asset', back_populates='target')
class Asset(Base):
 __tablename__ = 'assets'; id = Column(Integer, primary_key=True); target_id = Column(Integer, ForeignKey('targets.id')); url = Column(String); local_path = Column(String); findings = relationship('Finding', back_populates='asset'); target = relationship('Target', back_populates='assets')
class Finding(Base):
 __tablename__ = 'findings'; id = Column(Integer, primary_key=True); asset_id = Column(Integer, ForeignKey('assets.id')); type = Column(String); severity = Column(String); evidence = Column(Text); line = Column(Integer, nullable=True); asset = relationship('Asset', back_populates='findings')
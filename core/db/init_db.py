#!/usr/bin/env python3
"""Database initialization script - SAFE VERSION (doesn't drop existing tables)"""
import sys
sys.path.insert(0, '/app')

from core.db.session import engine, Base
from core.db.models import Target, Asset, Finding, SourceFile
from sqlalchemy import inspect

print('🔧 Checking database tables...')

# Check if tables already exist
inspector = inspect(engine)
existing_tables = inspector.get_table_names()

if existing_tables:
    print(f'✅ Found existing tables: {", ".join(existing_tables)}')
    print('📊 Database is already initialized. Skipping creation.')
else:
    print('🆕 No tables found. Creating new tables...')
    Base.metadata.create_all(bind=engine)
    print('✅ Database initialized!')
    print('\nCreated tables:')
    print('  - targets')
    print('  - source_files')
    print('  - assets')
    print('  - findings')
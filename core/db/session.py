from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os, time
def get_engine():
 url = os.getenv('DATABASE_URL')
 for i in range(20):
  try:
   e = create_engine(url)
   with e.connect(): return e
  except: time.sleep(3)
 return create_engine(url)
engine = get_engine()
SessionLocal = sessionmaker(bind=engine)
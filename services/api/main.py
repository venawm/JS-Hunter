from fastapi import FastAPI
from pydantic import BaseModel
from celery import Celery
import os
from core.db.session import engine, SessionLocal
from core.db.models import Base
Base.metadata.create_all(bind=engine)
app = FastAPI(); celery = Celery('api', broker=os.getenv('REDIS_URL'))
class ManualIn(BaseModel): domain: str; filename: str; code: str
@app.post('/blackops/manual')
def manual_scan(m: ManualIn):
 celery.send_task('titan.process_file', args=[m.domain, m.filename, m.code], queue='titan_queue')
 return {'status': 'Dispatched'}
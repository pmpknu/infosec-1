from fastapi import FastAPI

from app import models  # noqa: F401  # ensure models register with Base metadata
from app.db import Base, engine
from app.routers import auth, posts

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Infosec Lab API")

app.include_router(auth.router)
app.include_router(posts.router)

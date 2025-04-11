from fastapi import FastAPI, Request, Response
from .config import Config
from .routes import router

app = FastAPI(title="Minicord API",
              description="A secure messaging platform API",
              version="1.0.0")

app.include_router(router)

@app.on_event("startup")
async def startup_event():
    Config.validate()
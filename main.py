from fastapi import FastAPI
from backend.api.routes import router

app = FastAPI(
    title="DataLeakGuard",
    description="Privacy firewall that protects users before their prompts are sent to external AI models",
    version="0.1.0"
)

# Include the API routes
app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

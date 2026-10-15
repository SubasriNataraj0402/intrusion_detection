from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "AI-NIDS Threat Intelligence Platform"
    database_url: str = "sqlite:///./nids.db"
    jwt_secret: str = "change-this-secret-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 8

    capture_interface: str = "en0"
    capture_enabled: bool = False
    flow_timeout_seconds: float = 15.0
    # Excluded so the backend's own API/WebSocket traffic (dashboard polling,
    # the live-update socket) isn't captured and classified as if it were
    # monitored network traffic — relevant when frontend/backend/capture all
    # share one loopback interface, as in the local demo setup.
    capture_exclude_ports: list[int] = [8000]

    alert_confidence_threshold: float = 0.75

    gemini_api_key: str = ""
    gemini_model: str = "gemini-1.5-flash"

    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3001", "http://127.0.0.1:3001"]

    class Config:
        env_file = ".env"


settings = Settings()

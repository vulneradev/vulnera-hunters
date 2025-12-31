"""Configuration management for VulneraAI backend."""
import os
from dataclasses import dataclass
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

@dataclass
class AIConfig:
    """AI service configuration."""
    provider: str = os.getenv("AI_PROVIDER", "openai")
    api_key: str = os.getenv("AI_API_KEY", "")
    model: str = os.getenv("AI_MODEL", "gpt-4-mini")
    temperature: float = float(os.getenv("AI_TEMPERATURE", "0.7"))
    max_tokens: int = int(os.getenv("AI_MAX_TOKENS", "2000"))

@dataclass
class DatabaseConfig:
    """Database configuration."""
    url: str = os.getenv("DATABASE_URL", "postgresql://localhost/vulneraai")
    pool_size: int = int(os.getenv("DB_POOL_SIZE", "10"))
    timeout: int = int(os.getenv("DB_TIMEOUT", "30"))

@dataclass
class CacheConfig:
    """Redis cache configuration."""
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    ttl: int = int(os.getenv("CACHE_TTL", "3600"))

@dataclass
class SecurityConfig:
    """Security configuration."""
    jwt_secret: str = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
    jwt_algorithm: str = "HS256"
    api_rate_limit: int = int(os.getenv("API_RATE_LIMIT", "100"))

class AppConfig:
    """Main application configuration."""
    ai = AIConfig()
    db = DatabaseConfig()
    cache = CacheConfig()
    security = SecurityConfig()
    debug = os.getenv("DEBUG", "False").lower() == "true"
    log_level = os.getenv("LOG_LEVEL", "INFO")

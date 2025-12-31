"""Redis caching implementation."""
import json
import hashlib
from typing import Optional, Any, Callable
from functools import wraps
import redis
from core.config import AppConfig
from core.logger import setup_logger

logger = setup_logger(__name__)

class CacheManager:
    """Manages Redis cache connections."""
    
    _client: Optional[redis.Redis] = None
    
    @classmethod
    def get_client(cls) -> redis.Redis:
        """Get or create Redis client."""
        if cls._client is None:
            try:
                logger.info("Connecting to Redis...")
                cls._client = redis.from_url(
                    AppConfig.cache.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_keepalive=True
                )
                # Test connection
                cls._client.ping()
                logger.info("Redis connection established")
            except redis.ConnectionError as e:
                logger.warning(f"Redis connection failed: {str(e)}. Caching disabled.")
                cls._client = None
        return cls._client

class RedisCache:
    """Redis caching utility."""
    
    @staticmethod
    def _generate_key(prefix: str, *args, **kwargs) -> str:
        """Generate cache key from prefix and arguments."""
        key_data = f"{prefix}:{'_'.join(str(a) for a in args)}"
        if kwargs:
            key_data += f":{json.dumps(kwargs, sort_keys=True)}"
        
        # Hash long keys
        if len(key_data) > 100:
            key_data = f"{prefix}:{hashlib.md5(key_data.encode()).hexdigest()}"
        
        return key_data
    
    @staticmethod
    def get(key: str) -> Optional[Any]:
        """Get value from cache."""
        client = CacheManager.get_client()
        if client is None:
            return None
        
        try:
            value = client.get(key)
            if value:
                logger.debug(f"Cache hit: {key}")
                return json.loads(value)
        except (redis.ConnectionError, json.JSONDecodeError) as e:
            logger.warning(f"Cache get failed: {str(e)}")
        
        return None
    
    @staticmethod
    def set(key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache."""
        client = CacheManager.get_client()
        if client is None:
            return False
        
        try:
            ttl = ttl or AppConfig.cache.ttl
            client.setex(key, ttl, json.dumps(value))
            logger.debug(f"Cache set: {key}")
            return True
        except (redis.ConnectionError, json.JSONDecodeError) as e:
            logger.warning(f"Cache set failed: {str(e)}")
            return False
    
    @staticmethod
    def delete(key: str) -> bool:
        """Delete value from cache."""
        client = CacheManager.get_client()
        if client is None:
            return False
        
        try:
            client.delete(key)
            logger.debug(f"Cache deleted: {key}")
            return True
        except redis.ConnectionError as e:
            logger.warning(f"Cache delete failed: {str(e)}")
            return False
    
    @staticmethod
    def clear_pattern(pattern: str) -> int:
        """Clear all keys matching pattern."""
        client = CacheManager.get_client()
        if client is None:
            return 0
        
        try:
            keys = client.keys(pattern)
            if keys:
                return client.delete(*keys)
            return 0
        except redis.ConnectionError as e:
            logger.warning(f"Cache clear failed: {str(e)}")
            return 0

def cached(prefix: str, ttl: Optional[int] = None) -> Callable:
    """Decorator for caching function results."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            cache_key = RedisCache._generate_key(prefix, *args, **kwargs)
            
            # Try to get from cache
            cached_value = RedisCache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Call function and cache result
            result = await func(*args, **kwargs)
            RedisCache.set(cache_key, result, ttl)
            return result
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            cache_key = RedisCache._generate_key(prefix, *args, **kwargs)
            
            # Try to get from cache
            cached_value = RedisCache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Call function and cache result
            result = func(*args, **kwargs)
            RedisCache.set(cache_key, result, ttl)
            return result
        
        # Return appropriate wrapper
        import inspect
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator

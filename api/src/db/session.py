import asyncio

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from src.core.config import get_settings

settings = get_settings()

_engine_registry = {}
_sessionmaker_registry = {}
engine = None
async_session_maker = None


def _current_loop_key() -> int:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.get_event_loop_policy().get_event_loop()
    return id(loop)


def _ensure_engine() -> tuple:
    global engine, async_session_maker
    loop_key = _current_loop_key()
    if loop_key not in _engine_registry:
        db_engine = create_async_engine(
            settings.database_url,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_pre_ping=True,
            echo=False,
        )
        _engine_registry[loop_key] = db_engine
        _sessionmaker_registry[loop_key] = async_sessionmaker(
            db_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    engine = _engine_registry[loop_key]
    async_session_maker = _sessionmaker_registry[loop_key]
    return engine, async_session_maker


class Base(DeclarativeBase):
    pass


async def get_session() -> AsyncSession:
    _, session_factory = _ensure_engine()
    async with session_factory() as session:
        yield session


async def init_db() -> None:
    from src.db.models import Base as ModelsBase
    db_engine, _ = _ensure_engine()
    async with db_engine.begin() as conn:
        await conn.run_sync(ModelsBase.metadata.create_all)


async def close_db() -> None:
    db_engine, _ = _ensure_engine()
    await db_engine.dispose()
    loop_key = _current_loop_key()
    _engine_registry.pop(loop_key, None)
    _sessionmaker_registry.pop(loop_key, None)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool
from core.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_size=10,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=1800,
)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


# Schema is managed by Alembic (`alembic upgrade head`), not create_all().


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


def make_task_session_factory():
    """
    Engine + session factory for Celery tasks. Each task runs its own event loop
    via asyncio.run(), so pooled connections can't be shared across runs.
    Returns (engine, session_factory); the caller must dispose the engine.
    """
    task_engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
    return task_engine, async_sessionmaker(task_engine, expire_on_commit=False)

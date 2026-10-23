"""
Alembic environment configuration for ThreatPolish.

This file is executed by Alembic whenever a migration command runs.
It reads the database URL from ``app.core.config.settings`` (which in
turn reads from the ``.env`` file or environment variables) and wires
up our SQLAlchemy ``Base.metadata`` so that ``--autogenerate`` can
detect model changes.
"""

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# ---------------------------------------------------------------------------
# Import our application models and metadata
# ---------------------------------------------------------------------------
from app.core.config import settings
from app.db.base import Base

# Import all model modules so that Base.metadata is fully populated.
# Alembic's autogenerate inspects Base.metadata.tables — if a model
# file is not imported here, its tables will be invisible.
import app.models.event  # noqa: F401

# ---------------------------------------------------------------------------
# Alembic Config object
# ---------------------------------------------------------------------------
config = context.config

# Override the sqlalchemy.url from alembic.ini with our env-based setting.
# This means credentials are NEVER hardcoded in alembic.ini.
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Python logging from the config file
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Tell Alembic which metadata to compare against
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Emits SQL to stdout without connecting to the database.  Useful for
    generating migration scripts that a DBA can review before applying.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Creates an Engine and connects to the database so migrations are
    applied transactionally.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

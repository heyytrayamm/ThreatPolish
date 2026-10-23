"""
Shared SQLAlchemy declarative base for ThreatPolish models.

Every ORM model inherits from ``Base`` so that Alembic can discover
all tables through a single metadata object.
"""

from sqlalchemy.orm import DeclarativeBase, MappedAsDataclass


class Base(DeclarativeBase):
    """
    Root declarative base.

    Subclass this in every model file::

        from app.db.base import Base

        class Event(Base):
            __tablename__ = "events"
            ...
    """
    pass

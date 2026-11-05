import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Read the database URL from the environment (set in docker-compose.yml);
# fall back to a local SQLite file for development.
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/alfa_mail.db")

# check_same_thread is a SQLite-only option
connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}

# Create the engine to interact with the database
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=connect_args)

# Create a session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for our database models
Base = declarative_base()

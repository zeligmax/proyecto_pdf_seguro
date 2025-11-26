-- ============================================================
-- File Secure v3.2 - Database Initialization
-- PostgreSQL initialization script
-- ============================================================

-- Create database if it doesn't exist (run this manually if needed)
-- CREATE DATABASE filesecure_v3;

-- Connect to the database
\c filesecure_v3;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For text search optimization

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE filesecure_v3 TO filesecure;

-- Create indexes for common queries (will be created by SQLAlchemy, but included here for reference)
-- Tables will be created by SQLAlchemy/Alembic migrations

-- Set timezone
SET TIME ZONE 'UTC';

-- Display success message
DO $$
BEGIN
  RAISE NOTICE 'File Secure v3.2 database initialized successfully!';
  RAISE NOTICE 'Please run: python -m app.scripts.init_data to initialize system data';
END $$;

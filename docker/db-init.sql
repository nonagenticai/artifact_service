-- Local-development bootstrap, run once by the postgres image on first start.
--
-- The RLS migration (alembic 20261003_0001) refuses to run while the RUNTIME role
-- still holds CREATE on schema public -- the runtime must not be able to create
-- objects. In the default postgres image the database user owns schema public, so
-- a single-user setup would trip that guard. This creates the split the service
-- expects: `postgres` owns and migrates, `artifact_service` only reads/writes.
CREATE ROLE artifact_service LOGIN PASSWORD 'changeme' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE artifact_registry TO artifact_service;

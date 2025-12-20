-- Superset role
CREATE ROLE superset
  LOGIN
  PASSWORD 'superset';

-- Keycloak role
CREATE ROLE keycloak
  LOGIN
  PASSWORD 'keycloak';
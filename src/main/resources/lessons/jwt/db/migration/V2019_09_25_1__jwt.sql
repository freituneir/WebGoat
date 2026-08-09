CREATE TABLE jwt_keys(
  id varchar(20),
  key varchar(20)
);

INSERT INTO jwt_keys VALUES ('webgoat_key', SUBSTRING(REPLACE(CAST(UUID() AS VARCHAR(36)), '-', '') FROM 1 FOR 16));
INSERT INTO jwt_keys VALUES ('webwolf_key', SUBSTRING(REPLACE(CAST(UUID() AS VARCHAR(36)), '-', '') FROM 1 FOR 16));

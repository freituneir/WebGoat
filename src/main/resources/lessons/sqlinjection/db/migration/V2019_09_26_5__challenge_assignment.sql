CREATE TABLE sql_challenge_users(
  userid varchar(250),
  email varchar(30),
  password varchar(30)
);

INSERT INTO sql_challenge_users VALUES ('larry', 'larry@webgoat.org', SUBSTRING(CAST(UUID() AS VARCHAR(36)) FROM 1 FOR 30));
INSERT INTO sql_challenge_users VALUES ('tom', 'tom@webgoat.org', SUBSTRING(CAST(UUID() AS VARCHAR(36)) FROM 1 FOR 30));
INSERT INTO sql_challenge_users VALUES ('alice', 'alice@webgoat.org', SUBSTRING(CAST(UUID() AS VARCHAR(36)) FROM 1 FOR 30));
INSERT INTO sql_challenge_users VALUES ('eve', 'eve@webgoat.org', SUBSTRING(CAST(UUID() AS VARCHAR(36)) FROM 1 FOR 30));

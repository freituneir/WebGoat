CREATE TABLE access_control_users(
  username varchar(40),
  password varchar(40),
  admin boolean
);

INSERT INTO access_control_users VALUES ('Tom', CAST(UUID() AS VARCHAR(36)), false);
INSERT INTO access_control_users VALUES ('Jerry', CAST(UUID() AS VARCHAR(36)), true);
INSERT INTO access_control_users VALUES ('Sylvester', CAST(UUID() AS VARCHAR(36)), false);

CREATE TABLE user_system_data(
  userid int not null primary key,
  user_name varchar(12),
  password varchar(10),
  cookie varchar(30)
);

INSERT INTO user_system_data VALUES (101, 'jsnow', SUBSTRING(CAST(UUID() AS VARCHAR(36)) FROM 1 FOR 10), '');
INSERT INTO user_system_data VALUES (102, 'jdoe', SUBSTRING(CAST(UUID() AS VARCHAR(36)) FROM 1 FOR 10), '');
INSERT INTO user_system_data VALUES (103, 'jplane', SUBSTRING(CAST(UUID() AS VARCHAR(36)) FROM 1 FOR 10), '');
INSERT INTO user_system_data VALUES (104, 'jeff', SUBSTRING(CAST(UUID() AS VARCHAR(36)) FROM 1 FOR 10), '');
INSERT INTO user_system_data VALUES (105, 'dave', SUBSTRING(CAST(UUID() AS VARCHAR(36)) FROM 1 FOR 10), '');

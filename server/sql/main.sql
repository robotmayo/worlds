CREATE TABLE user_accounts(
  id serial PRIMARY KEY,
  username VARCHAR(64),
  password VARCHAR(80),
  email VARCHAR(128),
  created_on timestamp DEFAULT NOW(),
  last_updated timestamp
);

CREATE TABLE app_sessions (
  sid varchar NOT NULL,
	sess json NOT NULL,
	expire timestamp(6) NOT NULL
);

CREATE TABLE user_character(
  user_id int PRIMARY KEY,
  exp bigint,
  game_points bigint,
  game_cash int,
  level int
);

CREATE TABLE user_inventory(
  user_id int,
  item_id int,
  item_count int,
  obtained_on timestamp
);

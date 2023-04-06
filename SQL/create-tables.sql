DROP TABLE IF EXISTS account CASCADE;

CREATE TABLE account (
    email varchar(35),
    password char(60),
    rating float(2,1),
    active boolean default true
    PRIMARY KEY (`email`)
);
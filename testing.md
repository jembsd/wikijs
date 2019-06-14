<!-- TITLE: Testing -->
<!-- SUBTITLE: A quick summary of Testing -->


[Source](http://hyperpolyglot.org/db "Permalink to Relational Databases: PostgreSQL, MySQL, SQLite")

# Relational Databases: PostgreSQL, MySQL, SQLite

**databases:** [architecture][1] | [client][2] | [select][3] | [where][4] | [dates][5] | [join][6] | [aggregate][7] | [sort and limit][8] | [insert, update, and delete][9] | [schema][10] | [sequences][11] | [indices][12] | [import and export][13] | [script][14] | [function][15] | [query tuning][16] | [user][17] | [python][18] | [ruby][19] | [help][20] | [admin][21]

**sql:** [types][22] | [casts][23] | [literals][24] | [dates][5] | [identifiers][25] | [operators][26] | [functions][15] | [distinct][27] | [qualified *][28] | [regular expressions][29] | [sequences][11] | [group by][30] | [aggregation functions][31] | [window functions][32] | [where clause subqueries][33] | [join][6] | [from clause subquery][34] | [as][35] | [limit and offset][36] | [with][37] | [null][38] | [sets and multisets][39] | [session objects][40] | [scripts][41] | [reflection][42] | [sargable expressions][43] | [transactions][44] | [idempotent sql][45]

| ----- |
|  |  [postgresql][46] |  [mysql][47] |  [sqlite][48] |  
| [version used][49]  
  |  _9.1_ |  _MariaDB 5.5 with InnoDB_ |  _3.7_ |  
| [show version][50] |  _client:_  
$ psql \--version

_server:_  
> show server_version;

 |  _client:_  
$ mysql \--version

_server:_  
> status;

 |  $ sqlite3 \--version |  
| [architecture][51] |   | | |
| [engine][52] |  _in separate server process which communicates with client via TCP port or Unix domain socket_ |  _in separate server process which communicates with client via TCP port or Unix domain socket_ |  _contained in client library_ |  
| [data][53] |  _database consists of tables which represent relations_ |  _database consists of tables which represent relations_ |  _database consists of tables which represent relations_ |  
| [files][54] |  _each table corresponds to one or more files on the file system_ |   |  _database is stored in a single file_ |  
| [persistence][55] |  _a write ahead log is used to ensure durability without flushing tables to disk after each transaction_ |  _depends on storage engine; in InnoDB a redo log is used to ensure durability without flushing tables to disk after each transaction_ |  _database file is updated after each transaction_ |  
| [indices][56]  
  |  _tables can have any number of indices_ |  _tables can have any number of indices_ |  _tables can have any number of indices_ |  
| [transactions][57] |  _transactions can contain DML and DDL; row and table locking is available_ |  _transactions can contain DML; table locking is available; InnoDB storage engine uses row locking to implement transactions_ |   |  
| [security][58] |  _password protected user accounts with fine grained permissions_ |  _password protected user accounts with fine grained permissions_ |  _security and permissions as provided by file system for database file_ |  
| [server side language][59] |  _PL/pgSQL; server can be extended to support other languages_ |  _SQL/PSM_ |  _none_ |  
| [client][60] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [invoke client][61]  
  |  $ psql -U $USER -h localhost |  $ mysql -u $USER -h localhost -p |  $ sqlite3 DB_FILE |  
| [client help][62] |  ? |  ?  
?  
h  
help |  .help |  
| [default port][63]  
  |  _5432_ |  _3306_ |  _none_ |  
| [show databases][64] |  SELECT datname  
FROM pg_database;

l

 |  SHOW databases; |  .databases |  
| [switch database][65]  
  |  connect _database_; |  use _database_ |  attach "/tmp/db2" as db2;

_to disconnect:_  
detach db2;

 |  
| [current database][66]  
  |  SELECT current_database(); |  SELECT database(); |  _All attached files are current; names in one file may shadow another_ |  
| [chdir][67]  
  |  cd /tmp |  _none_ |  _none_ |  
| [shell command][68]  
  |  ! ls |  system ls |  _none_ |  
| run script |  i setup.sql |  source setup.sql |  .read setup.sql |  
| redirect output to file |  o /tmp/output.txt

_to discontinue redirection:_  
o

 |  tee /tmp/output.txt

_to discontinue redirection:_  
notee

 |  .output /tmp/output.txt

_to discontinue redirection:_  
.output stdout

 |  
| set column delimiter |  f "t" |  _none_ |  .separator "t" |  
| toggle between aligned and unaligned output |  a |  _none_ |  _none_ |  
| [select][69] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [select *][70] |  SELECT *  
FROM customers; |  SELECT *  
FROM customers; |  SELECT *  
FROM customers; |  
| [project columns][71] |  SELECT name, age  
FROM customers; |  SELECT name, age  
FROM customers; |  SELECT name, age  
FROM customers; |  
| [exclude column][72]  
  |  _none_ |  _none_ |  _none_ |  
| [project expression][73] |  SELECT 'Mr. ' || name, age + 3  
FROM customers; |  SELECT concat('Mr. ', name), age + 3  
FROM customers; |  SELECT 'Mr. ' || name, age + 3  
FROM customers; |  
| [rename column][74] |  SELECT name AS moniker  
FROM customers; |  SELECT name AS moniker  
FROM customers; |  SELECT name AS moniker  
FROM customers; |  
| [where][75] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [filter rows][76] |  SELECT *  
FROM customers  
WHERE name = 'Ed'; |  SELECT *  
FROM customers  
WHERE name = 'Ed'; |  SELECT *  
FROM customers  
WHERE name = 'Ed'; |  
| [comparison operators][77] |  SELECT * FROM customers WHERE age > 21;  
SELECT * FROM customers WHERE age < 21;  
SELECT * FROM customers WHERE age >= 21;  
SELECT * FROM customers WHERE age <= 21;  
SELECT * FROM customers WHERE age <> 21; |   |   |  
| [multiple conditions on field][78] |  SELECT *  
FROM customers  
WHERE age >= 21  
  AND age <= 65; |   |   |  
| [logical operators][79]  
  |  AND OR NOT |   |   |  
| [like][80] |  SELECT *  
FROM customers  
WHERE name LIKE 'Ed%'; |   |   |  
| [dates][81] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| current timestamp |  SELECT now();  
SELECT CURRENT_TIMESTAMP; |  select now();  
select current_timestamp; |  select current_timestamp; |  
| [join][82] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [inner join][83] |  SELECT *  
FROM customers c  
JOIN orders o  
  ON c.id = o.customer_id; |  SELECT *  
FROM customers c  
JOIN orders o  
  ON c.id = o.customer_id; |   |  
| [left outer join][84] |  _include customers with no orders:_  
SELECT *  
FROM customers c  
LEFT JOIN orders o  
  ON c.id = o.customer_id; |  _include customers with no orders:_  
SELECT *  
FROM customers c  
LEFT JOIN orders o  
  ON c.id = o.customer_id; |   |  
| [full outer join][85] |  _include customers with no orders and orders with no customers:_  
SELECT *  
FROM customers c  
FULL JOIN orders o  
  ON c.id = o.customer_id; |  SELECT *  
FROM customers c  
LEFT JOIN orders o  
  ON c.id = o.customer_id  
UNION  
SELECT *  
FROM customers c  
RIGHT JOIN orders o  
  ON c.id = o.customer_id; |   |  
| [cartesian join][86] |  SELECT *  
FROM rows, columns; |  SELECT *  
FROM rows, columns; |   |  
| [aggregate][87] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [row count][88]  
  |  SELECT count(*) FROM customers; |  select count(*) from customers; |  select count(*) from customers; |  
| [count of rows satisfying condition][89] |  SELECT count(*)  
FROM customers  
WHERE age > 21; |   |   |  
| [count distinct][90] |  SELECT count(DISTINCT name)  
FROM customers; |   |   |  
| [group by][91] |  SELECT count(*)  
FROM customers  
GROUP BY age; |   |   |  
| [aggregation operators][92] |   |   |   |  
| [sort and limit][93] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [sort in ascending order][94] |  SELECT *  
FROM customers  
ORDER BY name; |  select *  
from baz  
order by foo; |  select *  
from baz  
order by foo; |  
| [sort in descending order][95] |  SELECT *  
FROM customers  
ORDER BY name DESC; |  select *  
from baz  
order by foo desc; |  select *  
from baz  
order by foo desc; |  
| [sort by multiple columns][96] |  SELECT *  
FROM customers  
ORDER BY age, name; |   |   |  
| [single row][97] |  SELECT *  
FROM customers  
WHERE name = 'Ed'  
LIMIT 1; |  select *  
from customers  
where name = 'Ed'  
limit 1; |  select *  
from customers  
where name = 'Ed'  
limit 1; |  
| [limit][98] |  _first 10 customers:_  
SELECT *  
FROM customers  
ORDER BY name  
LIMIT 10; |  select *  
from customers  
limit 10; |  select *  
from customers  
limit 10; |  
| [offset][99] |  _second 10 customers:_  
SELECT *  
FROM customers  
ORDER BY name  
LIMIT 10  
OFFSET 10; |   |   |  
| [insert, update, and delete][100] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [insert][101] |  INSERT INTO customers (name, age)  
VALUES (34, 'Ed'); |  insert into foo (bar, baz)  
values (1, 'one'); |  insert into foo (bar, baz)  
values (1, 'one'); |  
| [update][102] |  UPDATE customers  
SET age = 35  
WHERE name = 'Ed'; |  update foo  
set baz = 'une'  
where bar = 1; |  update foo  
set baz = 'une'  
where bar = 1; |  
| [merge][103] |   |   |   |  
| [delete][104] |  DELETE FROM customers  
WHERE name = 'Ed'; |  delete from foo  
where bar = 1; |  delete from foo  
where bar = 1; |  
| [delete all rows][105] |  DELETE FROM customers;

_faster:_  
TRUNCATE customers;

 |  delete from foo;

_faster on 5.0.3 and later:_  
truncate foo;

 |  delete from foo; |  
| [schema][106] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [create table][107] |  CREATE TABLE customers (  
  name TEXT,  
  age INT  
); |  create table foo (  
  bar int,  
  baz text  
); |  create table foo (  
  bar int,  
  baz text  
); |  
| [drop table][108]  
  |  DROP TABLE customers; |  DROP TABLE customers; |  DROP TABLE customers; |  
| [show tables][109]  
  |  d |  show tables; |  .tables |  
| [describe table][110]  
  |  d _table_ |  desc _table_; |  .schema _table_ |  
| [export schema][111]  
  |  $ pg_dump -a _db_ > _db_.sql |  $ mysqldump \--d _db_ > _db_.sql |   |  
| [describe document][112]  
  |  _table determines row type_ |  _table determines row type_ |   |  
| [sequences][113] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [increment][114] |   |   |   |  
| [indices][115] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| show indices |  di |  show index from _table_; |  .indices |  
| create index |  CREATE INDEX foo_bar_idx on foo (bar); |  _InnoDB requires that the max length of a text or varchar column be less than 767 characters_  
create index foo_bar_idx on foo (bar); |  create index foo_bar_idx on foo ( bar ); |  
| drop index |  DROP INDEX foo_bar_idx; |  drop index foo_bar_idx on foo; |  drop index foo_bar_idx; |  
| create unique index |  CREATE UNIQUE INDEX foo_bar_idx ON foo (bar); |  create unique index foo_bar_idx on foo (bar); |  create unique index foo_bar_idx on foo ( bar ); |  
| create compound index |  CREATE INDEX foo_bar_baz_idx ON foo (bar, baz); |  create index foo_bar_baz_idx on foo (bar, baz); |  create index foo_bar_baz_idx on foo (bar, baz); |  
| index hint |   |   |   |  
| [import and export][116] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [import csv][117] |  $ echo $'1,"one, two, three"n2,fourn3,"fivensixnseven"' > /tmp/test.csv

$ echo 'create table test_csv ( col1 int, col2 text );' | psql

$ ( echo 'copy test_csv from stdin with (format csv); '; cat /tmp/test.csv ) | psql

_trim header if there is one:_  
( echo 'copy test_csv from stdin with (format csv); '; sed -n '2,$p' /tmp/test.csv ) | psql

 |   |  $ echo $'1,"one, two, three"n2,fourn3,"fivensixnseven"' > /tmp/test.csv

$ sqlite3

> create table test_csv ( col1 int, col2 text );

> .mode csv

> .import /tmp/test.csv test_csv

 |  
| [export csv][118] |  $ echo 'copy foo to stdout with (format csv);' | psql > /tmp/foo.csv |  grant FILE on *.* to 'joe'@'localhost';

SELECT *  
INTO OUTFILE '/tmp/dump.csv'  
FIELDS TERMINATED BY ','  
OPTIONALLY ENCLOSED BY '"'  
LINES TERMINATED BY 'n'  
FROM foo;

 |  .mode csv  
.output /tmp/foo.csv  
select * from foo; |  
| [script][119] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [run script][120] |  i foo.sql

$ psql -f foo.sql

 |  source foo.sql

$ mysql _db_ < foo.sql

 |  .read foo.sql |  
| [function][121] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [show functions][122] |  df; |  show function status;

show procedure status;

select routine_name  
from information_schema.routines;

 |   |  
| [show function source][123] |  df+ _func_name_; |   |   |  
| show built-in functions |  select proname from pg_proc;

select routine_name  
from information_schema.routines;

 |   |   |  
| define function |   |   |   |  
| [query tuning][124] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| explain plan |  EXPLAIN SELECT * FROM customers; |  EXPLAIN SELECT * FROM customers; |  explain select * from foo; |  
| query stats |  EXPLAIN ANALYZE SELECT * FROM customers; |   |  .stats on  
.stats off |  
| timer |   |   |  .timer on  
.time off |  
| stats tables |   |   |   |  
| [user][125] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [current user][126] |  select current_user; |  select user(); |  _none_ |  
| [list users][127] |  select usename  
from pg_user; |  _table only readable by root:_  
select user from mysql.user; |  _none_ |  
| [create user][128] |  _at sql prompt:_  
> create role fred with superuser  
  createdb createrole login;

_at cmd line; will prompt for privileges:_  
$ createuser fred

 |  create user 'fred'@'localhost' identified by 'abc123'; |  _none_ |  
| [switch user][129] |  set role fred; |   |   |  
| [drop user][130] |  > drop role fred;

$ dropuser fred

 |  drop user 'fred'@'localhost'; |  _none_ |  
| [set password][131] |  alter user fred with password 'xyz789'; |  set password for 'fred'@'localhost' = password('xyz789'); |   |  
| [grant][132] |   |  grant select on test.foo to 'fred'@'localhost'; |   |  
| [grant all][133] |   |  _table foo in database test:_  
grant all on test.foo to 'fred'@'localhost';

_all tables in database test:_  
grant all on test.* to 'fred'@'localhost';

 |   |  
| [revoke][134] |   |  revoke all on test.* from 'fred'@'localhost'; |   |  
| [python][135] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| install driver |  $ sudo pip install psycopg |  _make sure MySQL development files are installed:_  
$ sudo pip install MySQL-python |  _Python ships with a driver_ |  
| import driver |  import psycopg2 |  import MySQLdb |  import sqlite3 |  
| connect  
_open, close_ |  conn = psycopg2.connect(database='foo')

conn.close()

 |  conn = MySQLdb.Connect(  
  db='cust',  
  user='joe',  
  passwd='xyz789',  
  host='127.0.0.1')

conn.close()

 |  conn = sqlite3.connect('/PATH/TO/DBFILE')

conn.close()

 |  
| cursor  
_create, close_ |  cur = conn.cursor()

cur.close()

 |  cur = conn.cursor()

cur.close()

 |  cur = conn.cursor()

cur.close()

 |  
| execute |  cur.execute('select * from bar') |  cur.execute("select * from bar") |  cur.execute('select * from bar') |  
| bind variable |  cur.execute('select * from foo where bar = %s', vars=[1]) |  cur.execute("select * from foo where bar = %s", (1,)) |  cur.execute('select * from foo where bar = ?', (1,)); |  
| fetch all results |  # returns list of tuples:  
rows = cur.fetchall() |  rows = cur.fetchall() |  # returns list of tuples:  
rows = cur.fetchall() |  
| iterate through results |  for row in cur:  
  print(row[0]) |  for row in cur:  
  print(row[0]) |  for row in cur:  
  print(row[0]) |  
| fetch one result |  # returns a tuple:  
row = cur.fetchone() |  # returns a tuple:  
row = cur.fetchone() |  # returns a tuple:  
row = cur.fetchone() |  
| transaction |   |   |   |  
| [ruby][136] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| install driver |  $ sudo gem install ruby-pg |  $ sudo gem install mysql |  _Ruby ships with a driver_ |  
| import driver |  require 'pg' |  require 'mysql' |  require 'sqlite3' |  
| connect  
_open, close_ |  conn = PGconn.open(:dbname => 'foo')

_??_

 |  conn = Mysql.new  
conn.select_db("foo")

_??_

 |  conn = SQLite3::Database.new "/tmp/db"

conn.close()

 |  
| execute |  result = conn.exec("select * from foo;") |  stmt = con.prepare('select * from foo')  
stmt.execute |  rows = conn.execute("select * from foo") |  
| bind variable |   |  stmt = con.prepare('select * from foo where bar = ?')  
stmt.execute(1) |  rows = conn.execute("select * from foo where bar = ?", [1]) |  
| number of rows returned |  result.cmdtuples |  stmt.num_rows |  rows.size |  
| fetch a row |  # hash with column names as keys:  
result[0] |  # returns array:  
stmt.fetch |  rows[0] |  
| iterate through results |  result.each do |row|  
  puts row["bar"]  
end |  stmt.each do |row|  
  puts row[0]  
end |  rows.each do |row|  
  puts row[0]  
end |  
| transaction |   |   |   |  
| [help][137] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| man page |  $ man 1 psql  
$ man 7 copy  
$ man 7 create_table |   |   |  
| [admin][138] |   | | |
|  |  postgresql |  mysql |  sqlite |  
| [admin user][139] |  postgres |  root |  _none_ |  
| [server process][140] |  postgres |  mysqld |  _none_ |  
| [start server][141] |   |   |   |  
| [stop server][142] |   |   |   |  
| [config file][143] |   |   |   |  
| [reload config file][144] |   |   |   |  
| [data directory][145] |  $ postgres -D /PATH/TO/DATA/DIR |  $ mysqld \--datadir /PATH/TO/DATA/DIR |  _specified on command line_ |  
| [create database][146] |  _at sql prompt:_  
> create database foo;

_at command line:_  
$ createdb foo

 |  _User must have 'create' privilege._

_at sql prompt:_  
> create database foo;

_at command line:_  
$ mysqladmin create foo

 |   |  
| [drop database][147] |  > drop database foo;

$ dropdb foo

 |  _User must have 'drop' privilege._

_at sql prompt:_  
> drop database foo;

_at command line:_  
$ mysqladmin drop foo

 |   |  
| [backup database][148] |  $ pg_dump foo > /tmp/foo.sql

$ pg_dump -F=c foo > /tmp/foo.postgres

 |  $ mysqldump foo > /tmp/foo.sql |   |  
| [restore database][149] |  $ psql -f /tmp/foo.sql

$ pg_restore -d foo /tmp/foo.postgres

 |  $ mysql < /tmp/foo.sql |   |  
|  |  _________________________________ |  _________________________________ |  _________________________________ | 

The version used to test the examples in this sheet.

How to determine the version of a database engine.

**mysql:**

MySQL supports different storage engines. Each storage engine has its own size limits, and features such as indexes, transactions, locking and foreign key support aren't available for all storage engines.

Here is how to determine the storage engine used for a table:
    
    
    select engine
    from information_schema.tables
    where table_schema = 'test'
      and table_name = 'foo';
    

The location of the database engine.

How data is organized in a database.

How data is stored in files on the file system.

**postgresql:**

Tables are split into multiple files when they exceed 2G; large attributes are stored in separate TOAST files.

What durability guarantee is made and how this is accomplished.

Are indices available and what can be indexed.

Are transactions available and what can participate in a transaction.

Available security features.

Whether a server side programming language is available.

How to invoke the command line client.

**postgresql:**

If the database user is not specified, it will default to the operating system user. If the database is not specified, it will default to the operating system user. If the host is not specified, _psql_ will attempt to connect to a server on the local host using a Unix domain socket.

How to get a list of commands available at the command line client prompt.

The default port used by the client to connect to the server.

The default ports used by PostgreSQL and MySQL are defined in `/etc/services`.

List the available databases on a server.

How to switch between databases when using the command line SQL prompt.

The name of the startup file used by the client.

List the tables in the current database.

Show the columns for a table and their types.

How to run a SQL script at the command line.

List the stored functions in the current database.

How to create a database.

**postgresql:**

The user must have the `CREATEDB` privilege. When creating the database from the command line using `createdb`, the PostgreSQL user can be specified using the `-U` option.

How to drop a database.

_Writing SELECT queries for open-source databases._

The reader is assumed to have written SELECT queries with FROM, WHERE, GROUP BY, HAVING, and ORDER BY clauses.

When we say that something is _standard_, we mean it conforms to the most recent SQL standard.

When we say that something is _portable_, we mean works on PostgreSQL, MySQL, and SQLite.

A list of portable types:

* BOOLEAN
* INTEGER _or_ INT
* REAL
* DOUBLE PRECISION
* NUMERIC(_total digits_, _fractional digits_)
* NUMERIC(_total digits_)
* CHARACTER(_len_) _or_ CHAR(_len_)
* CHARACTER VARYING(_len_) _or_ VARCHAR(_len_)
* TIMESTAMP
* DATE
* TIME

Note that `NUMERIC(_len_)` defines an integer type.

**mysql:**

MySQL maps BOOLEAN to TINYINT(1); REAL and DOUBLE PRECISION to DOUBLE; NUMERIC to DECIMAL.

This is the standard and portable way to cast:
    
    
    SELECT cast('7' AS INTEGER) + 3;
    

The standard calls for implicit casts between numeric types.

The standard also calls for implicit casts between character types. In particular, character types can be concatenated, and the length of the concatenation type is the sum of the length of the argument types.

**postgresql:**

Other ways to cast:
    
    
    > SELECT '7'::INTEGER + 3;
    > SELECT INTEGER '7' + 3;
    

The type of string operations is TEXT, which is a character type of unlimited length.

It is an error to attempt to insert a string that is too long into a column with fixed or maximum length.

**mysql:**

When concatenating character types, the length of the type of the concatenation is the sum of the length of the type of the arguments.

MySQL silently truncates strings that are too long on insert.

**sqlite:**

SQLite does not enforce character type length limits.

The standard reserves these keywords: NULL, TRUE, and FALSE.

Numeric literals work like you would expect.

SQL strings are admirably simple. Single quote delimited, double the single quote to escape, double pipe for concatenation.

**postgresql:**

This code results in a type mismatch error:

Converting a string containing a hex digit to an integer:
    
    
    > select x'3bb'::int;
     int4 
    ------
      955
    

The `chr()` function takes an integer representing a Unicode point as an argument:
    
    
    > SELECT 'one' || chr(10) || 'two' || chr(10) || 'three';
     ?column? 
    ----------
     one     +
     two     +
     three
    
    > SELECT chr(x'3bb'::int);
     chr 
    -----
     λ
    

There is syntax for strings with C-style backslash escapes:
    
    
    select E'onentwonthree';
    

**mysql:**

TRUE and FALSE are synonyms for 1 and 0.

The `||` operator is used for logical disjunction. Use the `concat()` function for string concatenation.

> SELECT concat('one', char(10), 'two');
    
    
    +--------------------------------+
    | concat('one', char(10), 'two') |
    +--------------------------------+
    | one
    two                        |
    +--------------------------------+
    

**sqlite:**

SQLite does not have TRUE and FALSE literals. Use 1 and 0 instead.

Strings can be single quote or double quote delimited.

The standard provides the keywords CURRENT_TIME, CURRENT_DATE, and CURRENT_TIMESTAMP for observing the clock.

There are no date literals; strings are used instead. Inserting a string into a TIME, DATE, or TIMESTAMP column will work if [ISO 8601 format][150] is used.
    
    
    > CREATE TABLE foo (a DATE, b TIME, c TIMESTAMP);
    
    > INSERT INTO foo VALUES ('2012-10-19', '18:00:00', '2012-10-19 18:00:00');
    

This works in both MySQL and PostgreSQL:
    
    
    > SELECT date('2012-10-19'), time('18:00:00'), timestamp('2012-10-19 18:00:00');
    

EXTRACT, TIMESTAMP from DATE and TIME, STRFTIME, STRPTIME

_INTERVAL type and date arithmetic_

* TIMESTAMP - TIMESTAMP
* TIMESTAMP + INTERVAL and INTERVAL + TIMESTAMP
* INTERVAL + INTERVAL and INTERVAL - INTERVAL
* INTERVAL * NUMERIC and NUMERIC * INTERVAL
* INTERVAL / NUMERIC

**mysql:**

MySQL does not have an INTERVAL type. Subtracting two TIMESTAMPs yields a NUMERIC(20, 0) and subtracting two DATEs yields a NUMERIC(11, 0).

According to the standard, identifiers with unusual characters should be double quoted. A literal double quote is represented by two double quotes.

**mysql:**

MySQL uses backticks `` instead of double quotes "" to quote identifiers.

* AND OR NOT
* < > <= >= = != (<>)
* BETWEEN IN
* \+ - * / % ^
* & | # ~  << >>
* || LIKE (ESCAPE)
    
    
    -- select rows where foo.x ends with percent sign
    --
    SELECT *
    FROM foo
    WHERE x LIKE '%%' ESCAPE '';
    

_check mysql and sqlite_

_how to get a list of functions_

[MySQL 5.5 Functions and Operators][151]  
[MySQL 5.5 Function Index][152]  
[SQLite Core Functions][153]  
[SQLite Aggregate Functions][154]  
[SQLite Date and Time Functions][155]

Some of the places DISTINCT can be used:

* SELECT DISTINCT _expr ..._
* SELECT count(DISTINCT _expr_)
* UNION DISTINCT
* INTERSECT DISTINCT
* EXCEPT DISTINCT

UNION ALL, INTERSECT ALL, and EXCEPT ALL can be used to indicate multiset operations. UNION DISTINCT, INTERSECT DISTINCT, and EXCEPT DISTINCT indicate set operations. Since this is the default the use of DISTINCT is superfluous.
    
    
    -- Example of a qualified *: only 
    -- return rows from foo:
    --
    SELECT foo.*
    FROM foo
    JOIN bar
      ON foo.x = bar.x
    

SIMILAR TO _Postgres_

Here is the SQL standard syntax for external sequences:
    
    
    CREATE SEQUENCE foo;
    
    CREATE SEQUENCE bar START WITH 1000 INCREMENT BY 10 MAXVALUE 2000;
    
    SELECT NEXT VALUE FOR foo;
    
    ALTER SEQUENCE foo RESTART WITH 10;
    

Here is the SQL standard syntax for internal sequences. None of the open source databases support this syntax, however.
    
    
    CREATE TABLE foo (
      foo_id INTEGER GENERATED ALWAYS AS IDENTITY (
        START WITH 1
        INCREMENT BY 1
        MAXVALUE 10000)
    )
    

**postgresql:**

PostgreSQL lacks SQL standard syntax for reading external sequences:
    
    
    CREATE SEQUENCE foo;
    
    CREATE SEQUENCE bar START WITH 1000 INCREMENT BY 10 MAXVALUE 2000;
    
    SELECT nextval('foo');
    
    ALTER SEQUENCE foo RESTART WITH 10;
    
    SELECT setval('foo', 10);
    

The keywords `WITH` and `BY` are optional.

How to create an internal sequence:
    
    
    CREATE TABLE foo 
      foo_id SERIAL,
      foo_desc TEXT
    );
    

**mysql:**

MySQL does not have external sequences.

**sqlite:**

SQLite does not have external sequences.
    
    
    CREATE TABLE foo (
      foo_id INTEGER PRIMARY KEY AUTOINCREMENT,
      foo_desc TEXT
    );
    

GROUP BY, HAVING, and ORDER BY clauses can refer to SELECT list items by ordinal number. I don't think this is in the standard, but the feature is in PostgreSQL, MySQL, and SQLite.

| ----- |
|  |  postgresql |  mysql |  sqlite |  
|  |  count, sum, min, max, avg |  count, sum, min, max, avg |  count, sum, min, max, avg |  
|  |  count(distinct *)  
count(distinct _expr_)  
sum(distinct _expr_) |  count(distinct *)  
count(distinct _expr_)  
sum(distinct _expr_) |  count(distinct *)  
count(distinct _expr_)  
sum(distinct _expr_) |  
|  |  bit_and  
bit_or |  bit_and  
bit_or |   |  
|  |  bool_and  
bool_or |   |   |  
|  |  string_agg(_expr_, _delim_) |  group_concat(_expr_)  
group_concat(_expr_ separator _delim_) |   |  
|  |  array_agg |   |   |  
|  |  stddev_samp  
stddev_pop  
var_samp  
var_pop |  stddev_samp  
stddev_pop  
var_samp  
var_pop |   |  
|  |  cor(_X_, _Y_)  
cov_samp(_X_, _Y_)  
cor_pop(_X_, _Y_)  
regr_intercept(_X_, _Y_)  
regr_slope(_X_, _Y_) |   |   | 

_limits on use_

* can they be used with group by
* window functions in WHERE
* different window functions in SELECT

_usefulness_

* pct of total
* pct of category
* cumsum
* rank
    
    
    > SELECT state, fruit, avg(x) FROM produce GROUP BY state;
    ERROR:  column "produce.fruit" must appear in the GROUP BY clause or be used in an aggregate function
    LINE 1: SELECT state, fruit, avg(x) FROM produce GROUP BY state;
                          ^
    
    > SELECT state, fruit, avg(x) OVER (PARTITION BY state) FROM produce;
       state    |   fruit    |          avg           
    ------------+------------+------------------------
     arizona    | banana     | 1.00000000000000000000
     california | orange     |     8.6000000000000000
     california | banana     |     8.6000000000000000
     california | apple      |     8.6000000000000000
     california | banana     |     8.6000000000000000
     california | orange     |     8.6000000000000000
     nevada     | banana     |     6.3333333333333333
     nevada     | apple      |     6.3333333333333333
     nevada     | orange     |     6.3333333333333333
     oregon     | grapefruit |     2.5000000000000000
     oregon     | grapefruit |     2.5000000000000000
     washington | grapefruit |     2.5000000000000000
     washington | apple      |     2.5000000000000000
    

Subqueries can be used in a WHERE clause with EXISTS, IN, and the comparison operators: = < > <= >= != (<>).

The following two queries are equivalent.
    
    
    SELECT *
    FROM a, b
    WHERE a.x = b.x
      AND a.y > 0;
    
    
    
    SELECT *
    FROM a
      JOIN b
        ON a.x = b.x
    WHERE a.y > 0;
    

The latter form is perhaps preferred. The latter separates the join condition from the expression, keeping the expression simpler. Each JOIN clause must have an ON clause, reducing the chance of writing a Cartesian join by accident.

To perform an outer join—LEFT, RIGHT, or FULL—one must use a JOIN clause.

JOINs can be used to replace (NOT) EXISTS with a subquery:
    
    
    SELECT *
    FROM customers c
    WHERE NOT EXISTS (
      SELECT customer_id
      FROM orders o
      WHERE c.id = o.customer_id
    );
    
    
    
    SELECT c.*
    FROM customers c
      LEFT JOIN orders o
        ON c.id = o.customer_id
    WHERE o.customer_id is NULL;
    

Subqueries inside parens can appear in FROM and JOIN clauses. They must be given an alias.

Select list items and tables in FROM and JOIN clauses can be given an alias using AS. If the aliased item is a table or column its previous name is hidden. Use of the AS keyword is optional and can be omitted.

The standard is:
    
    
    OFFSET start { ROW | ROWS }
    FETCH { FIRST | NEXT } [ count ] { ROW | ROWS } ONLY
    

Of these databases, only PostgreSQL provides a mechanism for selecting the row number, and it requires using a window function: `row_number() OVER ()`.
    
    
    CREATE TABLE directed_edge (
      start_node TEXT,
      end_node TEXT
    );
    
    INSERT INTO directed_edge VALUES ( 'a', 'b');
    INSERT INTO directed_edge VALUES ( 'b', 'c');
    INSERT INTO directed_edge VALUES ( 'c', 'd');
    INSERT INTO directed_edge VALUES ( 'x', 'y');
    
    WITH RECURSIVE directed_path(start_node, end_node) AS (
      SELECT start_node, end_node
      FROM directed_edge
      UNION
      SELECT dp.start_node, de.end_node
      FROM directed_path AS dp
        JOIN directed_edge de
          ON dp.end_node = de.start_node
    )
    SELECT *
    FROM directed_path;
    
    
    
     start_node | end_node 
    ------------+----------
     a          | b
     b          | c
     c          | d
     x          | y
     a          | c
     b          | d
     a          | d
    

[NULL Handling in SQLite Versus Other Database Engines][156]

* NULL propagates in arithmetic: NULL + 0 is NULL, NULL * 0 is NULL.
* NULLs distinct in UNIQUE
* NULLs not distinct according to DISTINCT
* NULL is FALSE in CASE: "CASE WHEN null THEN 1 ELSE 0 END"
* THREE VALUE LOGIC: NULL OR TRUE is TRUE, NULL AND FALSE is FALSE.
    
    
    -- return 'bar' if foo is NULL
    coalesce(foo, 'bar')
    
    -- return NULL if foo is 'bar'
    nullif(foo, 'bar')
    
    
    
    SELECT 'foo', 3 UNION SELECT 'bar', 7;
    SELECT 'foo', 3 INTERSECT SELECT 'bar', 7;
    SELECT 'foo', 3 EXCEPT SELECT 'bar', 7;
    

ALL and DISTINCT can be used after UNION, INTERSECT, and EXCEPT to indicate multiset or set operations. Set operations (i.e. DISTINCT) are the default.

Temporary tables and variables.

The standard calls for a schema called `INFORMATION_SCHEMA`. The starting point for learning about a database is:
    
    
    SELECT * FROM INFORMATION_SCHEMA.TABLES;
    

The standard also provides these:
    
    
    > SELECT CURRENT_USER;
    > SELECT CURRENT_ROLE;
    > SELECT CURRENT_SCHEMA;
    > SELECT CURRENT_CATALOG;
    

**sqlite:**

SQLite does not have `INFORMATION_SCHEMA`. Use the `.schema` command to get a list of tables and their DDL.

[Sargable][157] (en.wikipedia.org)

Idempotent DDL scripts are desirable. `CREATE TABLE` statements fail if the table already exists. Both PostgreSQL and MySQL support `DROP TABLE foo IF EXISTS;` which is not part of the standard.

MERGE (MySQL REPLACE)

TEMP tables and WITH.

Query information_schema. This requires a language which can branch.

[1]: http://hyperpolyglot.org#arch
[2]: http://hyperpolyglot.org#client
[3]: http://hyperpolyglot.org#select
[4]: http://hyperpolyglot.org#where
[5]: http://hyperpolyglot.org#dates
[6]: http://hyperpolyglot.org#join
[7]: http://hyperpolyglot.org#aggregate
[8]: http://hyperpolyglot.org#sort-limit
[9]: http://hyperpolyglot.org#insert-update-delete
[10]: http://hyperpolyglot.org#schema
[11]: http://hyperpolyglot.org#sequences
[12]: http://hyperpolyglot.org#indices
[13]: http://hyperpolyglot.org#import-export
[14]: http://hyperpolyglot.org#script
[15]: http://hyperpolyglot.org#func
[16]: http://hyperpolyglot.org#query-tuning
[17]: http://hyperpolyglot.org#user
[18]: http://hyperpolyglot.org#python
[19]: http://hyperpolyglot.org#ruby
[20]: http://hyperpolyglot.org#help
[21]: http://hyperpolyglot.org#admin
[22]: http://hyperpolyglot.org#types
[23]: http://hyperpolyglot.org#casts
[24]: http://hyperpolyglot.org#literals
[25]: http://hyperpolyglot.org#identifiers
[26]: http://hyperpolyglot.org#op
[27]: http://hyperpolyglot.org#distinct
[28]: http://hyperpolyglot.org#qualified-asterisk
[29]: http://hyperpolyglot.org#regex
[30]: http://hyperpolyglot.org#group-by
[31]: http://hyperpolyglot.org#aggregation-func
[32]: http://hyperpolyglot.org#window-func
[33]: http://hyperpolyglot.org#where-subquery
[34]: http://hyperpolyglot.org#from-subquery
[35]: http://hyperpolyglot.org#as
[36]: http://hyperpolyglot.org#limit-offset
[37]: http://hyperpolyglot.org#with
[38]: http://hyperpolyglot.org#null
[39]: http://hyperpolyglot.org#set-multiset
[40]: http://hyperpolyglot.org#session-obj
[41]: http://hyperpolyglot.org#scripts
[42]: http://hyperpolyglot.org#reflection
[43]: http://hyperpolyglot.org#sargable-expr
[44]: http://hyperpolyglot.org#txn
[45]: http://hyperpolyglot.org#idempotent
[46]: http://hyperpolyglot.org#postgresql
[47]: http://hyperpolyglot.org#mysql
[48]: http://hyperpolyglot.org#sqlite
[49]: http://hyperpolyglot.org#version-used-note
[50]: http://hyperpolyglot.org#show-version-note
[51]: http://hyperpolyglot.org#arch-note
[52]: http://hyperpolyglot.org#engine-arch-note
[53]: http://hyperpolyglot.org#data-arch-note
[54]: http://hyperpolyglot.org#files-arch-note
[55]: http://hyperpolyglot.org#persistence-arch-note
[56]: http://hyperpolyglot.org#indices-arch-note
[57]: http://hyperpolyglot.org#txn-arch-note
[58]: http://hyperpolyglot.org#security-arch-note
[59]: http://hyperpolyglot.org#server-lang-arch-note
[60]: http://hyperpolyglot.org#client-note
[61]: http://hyperpolyglot.org#invoke-client-note
[62]: http://hyperpolyglot.org#client-help-note
[63]: http://hyperpolyglot.org#default-port-note
[64]: http://hyperpolyglot.org#show-db-note
[65]: http://hyperpolyglot.org#switch-db-note
[66]: http://hyperpolyglot.org#current-db-note
[67]: http://hyperpolyglot.org#chdir-note
[68]: http://hyperpolyglot.org#shell-cmd-note
[69]: http://hyperpolyglot.org#select-note
[70]: http://hyperpolyglot.org#select-star-note
[71]: http://hyperpolyglot.org#project-columns-note
[72]: http://hyperpolyglot.org#exclude-column-note
[73]: http://hyperpolyglot.org#project-expr-note
[74]: http://hyperpolyglot.org#rename-column-note
[75]: http://hyperpolyglot.org#where-note
[76]: http://hyperpolyglot.org#filter-rows-note
[77]: http://hyperpolyglot.org#comparison-op-note
[78]: http://hyperpolyglot.org#multiple-conditions-on-field-note
[79]: http://hyperpolyglot.org#logical-op-note
[80]: http://hyperpolyglot.org#like-note
[81]: http://hyperpolyglot.org#dates-note
[82]: http://hyperpolyglot.org#join-note
[83]: http://hyperpolyglot.org#inner-join-note
[84]: http://hyperpolyglot.org#left-outer-join-note
[85]: http://hyperpolyglot.org#full-outer-join-note
[86]: http://hyperpolyglot.org#cartesian-join-note
[87]: http://hyperpolyglot.org#aggregate-note
[88]: http://hyperpolyglot.org#row-count-note
[89]: http://hyperpolyglot.org#conditional-row-count-note
[90]: http://hyperpolyglot.org#count-distinct-note
[91]: http://hyperpolyglot.org#group-by-note
[92]: http://hyperpolyglot.org#aggregation-op-note
[93]: http://hyperpolyglot.org#sort-limit-note
[94]: http://hyperpolyglot.org#sort-ascending-note
[95]: http://hyperpolyglot.org#sort-descending-note
[96]: http://hyperpolyglot.org#sort-multiple-columns-note
[97]: http://hyperpolyglot.org#select-single-row-note
[98]: http://hyperpolyglot.org#limit-note
[99]: http://hyperpolyglot.org#offset-note
[100]: http://hyperpolyglot.org#insert-update-delete-note
[101]: http://hyperpolyglot.org#insert-note
[102]: http://hyperpolyglot.org#update-note
[103]: http://hyperpolyglot.org#merge-note
[104]: http://hyperpolyglot.org#delete-note
[105]: http://hyperpolyglot.org#delete-all-rows-note
[106]: http://hyperpolyglot.org#schema-note
[107]: http://hyperpolyglot.org#create-table-note
[108]: http://hyperpolyglot.org#drop-table-note
[109]: http://hyperpolyglot.org#show-tables-note
[110]: http://hyperpolyglot.org#describe-table-note
[111]: http://hyperpolyglot.org#export-schema-note
[112]: http://hyperpolyglot.org#describe-doc-note
[113]: http://hyperpolyglot.org#sequences-note
[114]: http://hyperpolyglot.org#incr-note
[115]: http://hyperpolyglot.org#indices-note
[116]: http://hyperpolyglot.org#import-export-note
[117]: http://hyperpolyglot.org#import-csv-note
[118]: http://hyperpolyglot.org#export-csv-note
[119]: http://hyperpolyglot.org#script-note
[120]: http://hyperpolyglot.org#sql-script-note
[121]: http://hyperpolyglot.org#func-note
[122]: http://hyperpolyglot.org#show-func-note
[123]: http://hyperpolyglot.org#show-func-src-note
[124]: http://hyperpolyglot.org#query-tuning-note
[125]: http://hyperpolyglot.org#user-note
[126]: http://hyperpolyglot.org#current-user-note
[127]: http://hyperpolyglot.org#list-users-note
[128]: http://hyperpolyglot.org#create-user-note
[129]: http://hyperpolyglot.org#switch-user-note
[130]: http://hyperpolyglot.org#drop-user-note
[131]: http://hyperpolyglot.org#set-password-note
[132]: http://hyperpolyglot.org#grant-note
[133]: http://hyperpolyglot.org#grant-all-note
[134]: http://hyperpolyglot.org#revoke-note
[135]: http://hyperpolyglot.org#python-note
[136]: http://hyperpolyglot.org#ruby-note
[137]: http://hyperpolyglot.org#help-note
[138]: http://hyperpolyglot.org#admin-note
[139]: http://hyperpolyglot.org#admin-user-note
[140]: http://hyperpolyglot.org#server-proc-note
[141]: http://hyperpolyglot.org#start-server-note
[142]: http://hyperpolyglot.org#stop-server-note
[143]: http://hyperpolyglot.org#config-file-note
[144]: http://hyperpolyglot.org#reload-config-file-note
[145]: http://hyperpolyglot.org#data-dir-note
[146]: http://hyperpolyglot.org#create-db-note
[147]: http://hyperpolyglot.org#drop-db-note
[148]: http://hyperpolyglot.org#backup-db-note
[149]: http://hyperpolyglot.org#restore-db-note
[150]: http://en.wikipedia.org/wiki/ISO_8601
[151]: http://dev.mysql.com/doc/refman/5.5/en/functions.html
[152]: http://dev.mysql.com/doc/refman/5.5/en/dynindex-function.html
[153]: http://www.sqlite.org/lang_corefunc.html
[154]: http://www.sqlite.org/lang_aggfunc.html
[155]: http://www.sqlite.org/lang_datefunc.html
[156]: http://www.sqlite.org/nulls.html
[157]: http://en.wikipedia.org/wiki/Sargable

  
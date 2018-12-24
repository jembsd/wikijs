<!-- TITLE: Mysql -->
<!-- SUBTITLE: A quick summary of Mysql -->


# MySQL Command Line Cheat Sheet

## Connection

These are my most often-used MySQL commands and queries.

### Connect to MySQL on the command line (replace USERNAME with your own):



```
mysql -u USERNAME -p
```

(You will then be prompted to enter your MySQL password.)

## MySQL Databases

### List all databases on the command line:



```
mysql> SHOW DATABASES;
```

### Create a database on the command line:



```
mysql> CREATE DATABASE database_name CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Replace database\_name, above, with your name of choice.

### Delete a database:



```
mysql> drop database database_name;
```

Replace database\_name, above, with the actual name of your database.

### Use (or select) a database:



```
mysql> USE database_name;
```

### Check which database is currently selected:



```
mysql> SELECT DATABASE();
```

### Backing up a database on the command line with mysqldump:



```
$ mysqldump --opt -u username -p database > database_backup.sql
```

(Use ‘`mysqldump --opt --all-databases > all_backup.sql`‘ to backup everything.)

### Import a `.sql` database file into MySQL on the command line:



```
mysql -u root -p database_name < /home/path/to/some_database_file.sql
```

(Replace “root” with your MySQL user name, if needed.)

## MySQL Users

### List all MySQL users in a database. This shows a table of each MySQL user with the host, username, and password:



```
mysql> select host, user, password from mysql.user;
```

### Delete a MySQL user:



```
mysql> DROP USER 'username'@'host';
```

### Create a MySQL user and set the user’s password:



```
CREATE USER username@host;
SET PASSWORD FOR username@host= PASSWORD("thePassword");
```

### Grant database access to a MySQL user:



```
GRANT ALL PRIVILEGES ON database_name.* TO username@host IDENTIFIED BY 'thePassword';
FLUSH PRIVILEGES;
```

## MySQL Tables

### List all tables of a MySQL database on the command line:



```
mysql> SHOW TABLES;
```

### Describing the format of a table:



```
mysql> DESCRIBE table_name;
```

Replace table\_name, above, with the actual name of your table.

### Create a table on the command line:



```
mysql> CREATE TABLE table_name (field1_name TYPE(SIZE), field2_name TYPE(SIZE));
```

### Example:



```
mysql> CREATE TABLE pet (name VARCHAR(20), sex CHAR(1), birth DATE);
```

### Delete a table (aka Drop a table):



```
mysql> DROP TABLE table_name;
```

Replace table\_name, above, with the actual name of the table you want to remove.

### Delete all rows from a table, while leaving the table in tact:



```
mysql> TRUNCATE TABLE table_name;
```

### Show all indexes (and keys) of a table:



```
mysql> SHOW INDEX FROM table_name;
```

### Add a PRIMARY KEY to a table, assigning an existing column as the PRIMARY KEY. The `bigint(20) NOT NULL` part will vary according the attributes of your column:



```
mysql> ALTER TABLE table_name MODIFY COLUMN column_name bigint(20) NOT NULL PRIMARY KEY;
```

Delete a PRIMARY KEY from a table. This is done in a different way than deleting a regular index.



```
mysql> ALTER TABLE table_name DROP PRIMARY KEY;
```

### Delete an index or key from a table:



```
mysql> DROP INDEX index_key_name ON table_name;
```

### Create an index on a table:



```
mysql> CREATE INDEX index_key_name ON table_name (col_name);
```

Create an index, sorted in descending order. The DESC order only works in MySQL version 8+.



```
mysql> CREATE INDEX index_key_name ON table_name (col_name DESC);
```

### Create an index on multiple columns:



```
mysql> CREATE INDEX index_col1_col2 ON table_name (col1, col2);
```



```
mysql> CREATE INDEX index_col1_col2 ON table_name (col1 DESC, col2);
```

### Remove a row based on the value of a field (column) in a table:



```
mysql> DELETE FROM table_name WHERE field_name = 'whatever';
```

Replace table\_name, above, with the actual name of your table. Replace field\_name, above, with the actual name of your field. Replace ‘whatever’ with the value you’re searching for.

### Selecting from tables

### To run a SELECT query from the command line, type:



```
mysql> SELECT * FROM TABLE_NAME WHERE FIELD_NAME = "field_value";
```

### Retrieving information from a table (general):



```
mysql> SELECT from_columns FROM table WHERE conditions;
```

### Retrieve **all** rows from a MySQL table:



```
mysql> SELECT * FROM table;
```

### Retrieve some rows, those with a field that has a specified value:



```
mysql> SELECT * FROM table WHERE field_name = "value";
```

### Retrieve table rows based on multiple critera:



```
SELECT * FROM table WHERE field1 = "value1" AND field2 = "value2";
```

### Update a value for a row that has another value set to a specified value:



```
mysql> UPDATE TABLE SET column_1_name = "new_value" WHERE column_2_name = "value";
```

### To UPDATE a certain field value (dependent on the current/old value) in a MySQL database from the command line, type:



```
mysql> UPDATE table_name SET field_name = "new_value" WHERE field_name = "old_value";
```

### To UPDATE a certain field value, regardless of the current value, just use:



```
mysql> UPDATE table_name SET field_name = "new_value";
```

### Replace a string in a MySQL table. The WHERE clause is not necessary, but it can speed up the query in a very large table:



```
UPDATE table_name
SET field_name = REPLACE(field_name, 'old string to be replaced', 'new string')
WHERE field_name LIKE '%old string to be replaced%';
```

### Load tab-delimited data into a table:



```
mysql> LOAD DATA LOCAL INFILE "infile.txt" INTO TABLE table_name;
```

(Use n for NULL)

### Inserting one row at a time:



```
mysql> INSERT INTO table_name VALUES ('MyName', 'MyOwner', '2002-08-31');
```

(Use NULL for NULL)

### Reloading a new data set into existing table:



```
mysql> SET AUTOCOMMIT=1; # used for quick recreation of table
mysql> DELETE FROM pet;
mysql> LOAD DATA LOCAL INFILE "infile.txt" INTO TABLE table;
```

### Selecting specific columns:



```
mysql> SELECT column_name FROM table;
```

### Retrieving unique output records:



```
mysql> SELECT DISTINCT column_name FROM table;
```

### Sorting:



```
mysql> SELECT col1, col2 FROM table ORDER BY col2;
```

### Backwards: SELECT col1, col2 FROM table ORDER BY col2 DESC;

### Date calculations:



```
mysql> SELECT CURRENT_DATE, (YEAR(CURRENT_DATE)-YEAR(date_col)) AS time_diff [FROM table];
```

MONTH(some\_date) extracts the month value and DAYOFMONTH() extracts day.

### Pattern Matching:



```
mysql> SELECT * FROM table WHERE rec LIKE "blah%";
```

(% is wildcard – arbitrary \# of chars)  
### Find 5-char values: SELECT \* FROM table WHERE rec like “\_\_\_\_\_”;  
(\_ is any single character)

### Extended Regular Expression Matching:



```
mysql> SELECT * FROM table WHERE rec RLIKE "^b$";
```

(. for char, \[…\] for char class, \* for 0 or more instances  
^ for beginning, {n} for repeat n times, and $ for end)  
(RLIKE or REGEXP)  
To force case-sensitivity, use “REGEXP BINARY”

### Count all rows in a table:



```
mysql> SELECT COUNT(*) FROM table_name;
```

### Selecting from multiple tables:

(Example)



```
mysql> SELECT pet.name, comment FROM pet, event WHERE pet.name = event.name;
```

(You can join a table to itself to compare by using ‘AS’)

### Maximum value:



```
mysql> SELECT MAX(col_name) AS label FROM table;
```

### Auto-incrementing rows:



```
mysql> CREATE TABLE table (number INT NOT NULL AUTO_INCREMENT, name CHAR(10) NOT NULL);
mysql> INSERT INTO table (name) VALUES ("tom"),("dick"),("harry");
```

### Adding a column to an already-created table:



```
mysql> ALTER TABLE tbl ADD COLUMN [column_create syntax] AFTER col_name;
```

### Removing a column:



```
mysql> ALTER TABLE tbl DROP COLUMN col;
```

## Misc

### Batch mode (feeding in a script):



```
$ mysql -u user -p < batch_file
```

(Use -t for nice table layout and -vvv for command echoing.)  
### Alternatively:



```
mysql> source batch_file;
```

<span id="logo">[Isabel Castillo](https://isabelcastillo.com/ "WordPress Tutorials, Help and Code Snippets For Web Development")</span>☰

-   <span id="menu-item-1345">[Code](https://isabelcastillo.com/journal "Isabel Castillo’s Code Snippets – Code Journal")</span>
-   <span id="menu-item-2916">[Free Plugins](https://isabelcastillo.com/free-plugins "Free WordPress Plugins")</span>
-   <span id="menu-item-2344">[Docs](https://isabelcastillo.com/docs/ "Documentation")</span>

#### Web & Software Developer

<span itemprop="image" itemscope="" itemtype="https://schema.org/ImageObject"></span>

# MySQL Command Line Cheat Sheet

Updated April 23, 2018

<span itemprop="publisher" itemscope="" itemtype="https://schema.org/Organization"></span>

<span itemprop="logo" itemscope="" itemtype="https://schema.org/ImageObject"></span>

    <span class="comments-link">[1 Comment](https://isabelcastillo.com/mysql-command-line-cheat-sheet#comments)</span>  
Originally posted October 7, 2015

<span itemprop="articleBody"></span>

These are my most often-used MySQL commands and queries.

Connect to MySQL on the command line (replace USERNAME with your own):

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql -u USERNAME -p
```

(You will then be prompted to enter your MySQL password.)

## MySQL Databases

List all databases on the command line:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SHOW DATABASES;
```

Create a database on the command line:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> CREATE DATABASE database_name CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Replace database\_name, above, with your name of choice.

Delete a database:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> drop database database_name;
```

Replace database\_name, above, with the actual name of your database.

Use (or select) a database:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> USE database_name; 
```

Check which database is currently selected:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT DATABASE();
```

Backing up a database on the command line with mysqldump:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
$ mysqldump --opt -u username -p database > database_backup.sql
```

(Use ‘`mysqldump --opt --all-databases > all_backup.sql`‘ to backup everything.)

Import a `.sql` database file into MySQL on the command line:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql -u root -p database_name < /home/path/to/some_database_file.sql
```

(Replace “root” with your MySQL user name, if needed.)

## MySQL Users

List all MySQL users in a database. This shows a table of each MySQL user with the host, username, and password:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> select host, user, password from mysql.user;
```

Delete a MySQL user:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> DROP USER 'username'@'host';
```

Create a MySQL user and set the user’s password:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
CREATE USER username@host;
SET PASSWORD FOR username@host= PASSWORD("thePassword");
```

Grant database access to a MySQL user:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
GRANT ALL PRIVILEGES ON database_name.* TO username@host IDENTIFIED BY 'thePassword';
FLUSH PRIVILEGES;
```

## MySQL Tables

List all tables of a MySQL database on the command line:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SHOW TABLES;
```

Describing the format of a table:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> DESCRIBE table_name;
```

Replace table\_name, above, with the actual name of your table.

Create a table on the command line:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> CREATE TABLE table_name (field1_name TYPE(SIZE), field2_name TYPE(SIZE));
```

Example:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> CREATE TABLE pet (name VARCHAR(20), sex CHAR(1), birth DATE);
```

Delete a table (aka Drop a table):

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> DROP TABLE table_name;
```

Replace table\_name, above, with the actual name of the table you want to remove.

Delete all rows from a table, while leaving the table in tact:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> TRUNCATE TABLE table_name;
```

Show all indexes (and keys) of a table:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SHOW INDEX FROM table_name;
```

Add a PRIMARY KEY to a table, assigning an existing column as the PRIMARY KEY. The `bigint(20) NOT NULL` part will vary according the attributes of your column:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> ALTER TABLE table_name MODIFY COLUMN column_name bigint(20) NOT NULL PRIMARY KEY;
```

Delete a PRIMARY KEY from a table. This is done in a different way than deleting a regular index.

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> ALTER TABLE table_name DROP PRIMARY KEY;
```

Delete an index or key from a table:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> DROP INDEX index_key_name ON table_name;
```

Create an index on a table:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> CREATE INDEX index_key_name ON table_name (col_name);
```

Create an index, sorted in descending order. The DESC order only works in MySQL version 8+.

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> CREATE INDEX index_key_name ON table_name (col_name DESC);
```

Create an index on multiple columns:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> CREATE INDEX index_col1_col2 ON table_name (col1, col2);
```

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> CREATE INDEX index_col1_col2 ON table_name (col1 DESC, col2);
```

Remove a row based on the value of a field (column) in a table:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> DELETE FROM table_name WHERE field_name = 'whatever'; 
```

Replace table\_name, above, with the actual name of your table. Replace field\_name, above, with the actual name of your field. Replace ‘whatever’ with the value you’re searching for.

### Selecting from tables

To run a SELECT query from the command line, type:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT * FROM TABLE_NAME WHERE FIELD_NAME = "field_value";
```

Retrieving information from a table (general):

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT from_columns FROM table WHERE conditions;
```

Retrieve **all** rows from a MySQL table:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT * FROM table;
```

Retrieve some rows, those with a field that has a specified value:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT * FROM table WHERE field_name = "value";
```

Retrieve table rows based on multiple critera:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
SELECT * FROM table WHERE field1 = "value1" AND field2 = "value2";
```

Update a value for a row that has another value set to a specified value:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> UPDATE TABLE SET column_1_name = "new_value" WHERE column_2_name = "value";
```

To UPDATE a certain field value (dependent on the current/old value) in a MySQL database from the command line, type:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> UPDATE table_name SET field_name = "new_value" WHERE field_name = "old_value";
```

To UPDATE a certain field value, regardless of the current value, just use:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> UPDATE table_name SET field_name = "new_value";
```

Replace a string in a MySQL table. The WHERE clause is not necessary, but it can speed up the query in a very large table:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
UPDATE table_name
SET field_name = REPLACE(field_name, 'old string to be replaced', 'new string')
WHERE field_name LIKE '%old string to be replaced%';
```

Load tab-delimited data into a table:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> LOAD DATA LOCAL INFILE "infile.txt" INTO TABLE table_name;
```

(Use n for NULL)

Inserting one row at a time:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> INSERT INTO table_name VALUES ('MyName', 'MyOwner', '2002-08-31');
```

(Use NULL for NULL)

Reloading a new data set into existing table:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SET AUTOCOMMIT=1; # used for quick recreation of table
mysql> DELETE FROM pet;
mysql> LOAD DATA LOCAL INFILE "infile.txt" INTO TABLE table;
```

Selecting specific columns:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT column_name FROM table;
```

Retrieving unique output records:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT DISTINCT column_name FROM table;
```

Sorting:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT col1, col2 FROM table ORDER BY col2;
```

Backwards: SELECT col1, col2 FROM table ORDER BY col2 DESC;

Date calculations:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT CURRENT_DATE, (YEAR(CURRENT_DATE)-YEAR(date_col)) AS time_diff [FROM table];
```

MONTH(some\_date) extracts the month value and DAYOFMONTH() extracts day.

Pattern Matching:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT * FROM table WHERE rec LIKE "blah%";
```

(% is wildcard – arbitrary \# of chars)  
Find 5-char values: SELECT \* FROM table WHERE rec like “\_\_\_\_\_”;  
(\_ is any single character)

Extended Regular Expression Matching:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT * FROM table WHERE rec RLIKE "^b$";
```

(. for char, \[…\] for char class, \* for 0 or more instances  
^ for beginning, {n} for repeat n times, and $ for end)  
(RLIKE or REGEXP)  
To force case-sensitivity, use “REGEXP BINARY”

Count all rows in a table:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT COUNT(*) FROM table_name;
```

Selecting from multiple tables:

(Example)

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT pet.name, comment FROM pet, event WHERE pet.name = event.name;
```

(You can join a table to itself to compare by using ‘AS’)

Maximum value:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> SELECT MAX(col_name) AS label FROM table;
```

Auto-incrementing rows:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> CREATE TABLE table (number INT NOT NULL AUTO_INCREMENT, name CHAR(10) NOT NULL);
mysql> INSERT INTO table (name) VALUES ("tom"),("dick"),("harry");
```

Adding a column to an already-created table:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> ALTER TABLE tbl ADD COLUMN [column_create syntax] AFTER col_name;
```

Removing a column:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> ALTER TABLE tbl DROP COLUMN col;
```

## Misc

Batch mode (feeding in a script):

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
$ mysql -u user -p < batch_file
```

(Use -t for nice table layout and -vvv for command echoing.)  
Alternatively:

<span itemprop="programmingLanguage" itemscope="" itemtype="http://schema.org/ComputerLanguage"></span>

``` brush:
mysql> source batch_file;
```

Posted in [MySQL Code](https://isabelcastillo.com/category/mysql-code)

Tags: [cheat sheets](https://isabelcastillo.com/tag/cheatsheets) [SQL queries](https://isabelcastillo.com/tag/sql-queries)  

<a href="https://twitter.com/share?text=MySQL+Command+Line+Cheat+Sheet&amp;url=https%3A%2F%2Fisabelcastillo.com%2Fmysql-command-line-cheat-sheet&amp;hashtags=code" class="icon-twitter as-twitter">Tweet</a> <a href="http://www.facebook.com/sharer.php?u=https%3A%2F%2Fisabelcastillo.com%2Fmysql-command-line-cheat-sheet" class="icon-facebook as-facebook">Share</a> <a href="https://plus.google.com/share?url=https%3A%2F%2Fisabelcastillo.com%2Fmysql-command-line-cheat-sheet" class="icon-gplus as-gplus">Share</a>

#### By <span itemprop="author" itemscope="" itemtype="http://schema.org/Person"><span itemprop="name">Isabel Castillo</span></span>

<a href="https://github.com/isabelc" class="followme" title="github Isabel"><em></em></a><a href="https://profiles.wordpress.org/isabel104" class="followme" title="WordPress Isabel"><em></em></a><a href="https://plus.google.com/+IsabelCastillo" class="followme"><em></em></a><a href="https://twitter.com/maidenphp" class="followme"><em></em></a>

### Related Resources

-   [MySQL Queries To Change WordPress From HTTP to HTTPS In The Database](https://isabelcastillo.com/mysql-wordpress-http-to-https "MySQL Queries To Change WordPress From HTTP to HTTPS In The Database")
-   [SQL Query – Change siteurl in wp\_options Table For All Sites in WP Multisite](https://isabelcastillo.com/sql-query-change-siteurl-in-wp_options-table-for-all-sites-in-wp-multisite "SQL Query – Change siteurl in wp_options Table For All Sites in WP Multisite")
-   [SQL Query – Change home url in wp\_options for all sites in WP Multisite](https://isabelcastillo.com/sql-query-change-home-url-wp_options-multisite "SQL Query – Change home url in wp_options for all sites in WP Multisite")

### We've One Response

1.  <span itemprop="name">moyu</span>

    [January 9th, 2016 at 10:45 pm](https://isabelcastillo.com/mysql-command-line-cheat-sheet#comment-44302)
    great tutorials!

    <a href="https://isabelcastillo.com/mysql-command-line-cheat-sheet?replytocom=44302#respond" class="comment-reply-link">Reply <span>↓</span></a>

    <img src="https://secure.gravatar.com/avatar/eeddf4426a15a4ec71c41ce69886988a" alt="avatar" class="avatar photo" width="80" height="80" />

### Questions and Comments are Welcome <span class="small"><a href="/mysql-command-line-cheat-sheet#respond" id="cancel-comment-reply-link">Cancel reply</a></span>

Your email address will not be published. All comments will be moderated.

Comment

Please wrap code in "code" bracket tags like this:

    [code]

    YOUR CODE HERE 

    [/code]

Name <span class="required">\*</span>

Email <span class="required">\*</span>

 Notify me when new comments are added.

Current ye@r <span class="required">\*</span>

Leave this field empty

-   

-   ### Related

    -   [MySQL Queries To Change WordPress From HTTP to HTTPS In The Database](https://isabelcastillo.com/mysql-wordpress-http-to-https "MySQL Queries To Change WordPress From HTTP to HTTPS In The Database")
    -   [SQL Query – Change siteurl in wp\_options Table For All Sites in WP Multisite](https://isabelcastillo.com/sql-query-change-siteurl-in-wp_options-table-for-all-sites-in-wp-multisite "SQL Query – Change siteurl in wp_options Table For All Sites in WP Multisite")
    -   [SQL Query – Change home url in wp\_options for all sites in WP Multisite](https://isabelcastillo.com/sql-query-change-home-url-wp_options-multisite "SQL Query – Change home url in wp_options for all sites in WP Multisite")
    -   [Change Custom Menu Links in WP from HTTP to HTTPS via MySQL](https://isabelcastillo.com/custom-menu-links-https-mysql "Change Custom Menu Links in WP from HTTP to HTTPS via MySQL")

-   #### Recent Comments

    -   <span class="comment-author-link">Mark</span> on [MySQL Queries To Change WordPress From HTTP to HTTPS In The Database](https://isabelcastillo.com/mysql-wordpress-http-to-https#comment-47548)
    -   <span class="comment-author-link">Isabel</span> on [MySQL Queries To Change WordPress From HTTP to HTTPS In The Database](https://isabelcastillo.com/mysql-wordpress-http-to-https#comment-47547)
    -   <span class="comment-author-link">Isabel</span> on [Redirect To HTTPS, But Only Apply it to One Domain on GoDaddy](https://isabelcastillo.com/redirect-to-https#comment-47546)
    -   <span class="comment-author-link">mark</span> on [MySQL Queries To Change WordPress From HTTP to HTTPS In The Database](https://isabelcastillo.com/mysql-wordpress-http-to-https#comment-47545)
    -   <span class="comment-author-link">Julien</span> on [Let Editor Manage Users in WordPress](https://isabelcastillo.com/editor-role-manage-users-wordpress#comment-47544)
    -   <span class="comment-author-link">Dan Menapace</span> on [Redirect To HTTPS, But Only Apply it to One Domain on GoDaddy](https://isabelcastillo.com/redirect-to-https#comment-47543)
    -   <span class="comment-author-link">seb</span> on [Add Google Adsense To WordPress AMP Plugin (Accelerated Mobile Pages)](https://isabelcastillo.com/google-adsense-wordpress-amp#comment-47541)
    -   <span class="comment-author-link">Mia</span> on [MySQL Queries To Change WordPress From HTTP to HTTPS In The Database](https://isabelcastillo.com/mysql-wordpress-http-to-https#comment-47536)
    -   <span class="comment-author-link">Pedro</span> on [Add Google Adsense AUTO ADS To AMP for WordPress](https://isabelcastillo.com/auto-ads-amp-wordpress#comment-47535)
    -   <span class="comment-author-link">Pedro</span> on [Add Google Adsense AUTO ADS To AMP for WordPress](https://isabelcastillo.com/auto-ads-amp-wordpress#comment-47534)

<span class="small">© Copyright 2010–2018 [Isabel Castillo.](https://isabelcastillo.com/) [Terms of Use.](https://isabelcastillo.com/legal/terms-of-use) [Privacy.](https://isabelcastillo.com/legal/privacy "Privacy Policy") [Contact Isabel](https://isabelcastillo.com/email-isabel/ "Contact Isabel")</span>

<!-- TITLE: Testing -->
<!-- SUBTITLE: A quick summary of Testing -->

# Header
How does it work?

The vulnerability stems from unsanitized user-input. LFI is particularly common in php-sites.

Here is an example of php-code vulnerable to LFI. As you can see we just pass in the url-parameter into the require-function without any sanitization. So the user can just add the path to any file.

```php
$file = $_GET['page'];
require($file);
In this example the user could just enter this string and retrieve the /etc/passwd file.

http://example.com/page=../../../../../../etc/passwd
```

**Bold**

> Note

__Emphasis__

:smile:

:) 

-----



|HEader1|Header2|
|--------|---------|
|Yes.      |Ok.          |

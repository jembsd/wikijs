<!-- TITLE: Testing -->
<!-- SUBTITLE: A quick summary of Testing -->

---
lang: en
title: 'Scripting Languages I: Node.js, Python, PHP, Ruby - Hyperpolyglot'
---

::: {#container-wrap-wrap}
::: {#container-wrap}
::: {#container}
::: {#header}
[Hyperpolyglot](/)
==================
:::

::: {#content-wrap}
::: {#main-content}
::: {#page-title}
Scripting Languages I: Node.js, Python, PHP, Ruby
:::

::: {#page-content}
[]{#top}*a side-by-side reference sheet*

**sheet one:** [version](#version) \| [grammar and
execution](#grammar-execution) \| [variables and expressions](#var-expr)
\| [arithmetic and logic](#arithmetic-logic) \| [strings](#strings) \|
[regexes](#regexes) \| [dates and time](#dates-time) \|
[arrays](#arrays) \| [dictionaries](#dictionaries) \|
[functions](#functions) \| [execution control](#execution-control) \|
[exceptions](#exceptions) \| [threads](#threads)

**[sheet two](/scripting2):** [streams](/scripting2#streams) \|
[asynchronous events](/scripting2#async) \| [files](/scripting2#files)
\| [file formats](/scripting2#file-fmt) \|
[directories](/scripting2#directories) \| [processes and
environment](/scripting2#processes-environment) \| [option
parsing](/scripting2#option-parsing) \| [libraries and
namespaces](/scripting2#libraries-namespaces) \|
[objects](/scripting2#objects) \| [reflection](/scripting2#reflection)
\| [net and web](/scripting2#net-web) \|
[databases](/scripting2#databases) \| [unit
tests](/scripting2#unit-tests) \| [debugging](/scripting2#debugging)

[]{#version}[version](#version-note)
:::
:::
:::
:::
:::
:::

node.js

python

php

ruby

[]{#version-used}[version used](#version-used-note)\
[ ]{style="white-space: pre-wrap;"}

[*6.11*]{style="color: gray"}

[*3.6*]{style="color: gray"}

[*7.0*]{style="color: gray"}

[*2.3*]{style="color: gray"}

[]{#version}[show version](#version-note)\
[ ]{style="white-space: pre-wrap;"}

\$ node [\--]{style="white-space: pre-wrap;"}version

\$ python -V\
\$ python [\--]{style="white-space: pre-wrap;"}version

\$ php [\--]{style="white-space: pre-wrap;"}version

\$ ruby [\--]{style="white-space: pre-wrap;"}version

[]{#implicit-prologue}[implicit prologue](#implicit-prologue-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} npm install
lodash]{style="color: gray"}\
const \_ = require(\'lodash\');

import os, re, sys

[\# sudo apt install php-mbstring]{style="color: gray"}

[*none*]{style="color: gray"}

[]{#grammar-execution}[grammar and execution](#grammar-execution-note)

node.js

python

php

ruby

[]{#interpreter}[interpreter](#interpreter-note)\
[ ]{style="white-space: pre-wrap;"}

\$ node foo.js

\$ python foo.py

\$ php -f foo.php

\$ ruby foo.rb

[]{#repl}[repl](#repl-note)\
[ ]{style="white-space: pre-wrap;"}

\$ node

\$ python

\$ php -a

\$ irb

[]{#cmd-line-program}[command line program](#cmd-line-program-note)

\$ node -e \"console.log(\'hi!\');\"

\$ python -c \'print(\"hi!\")\'

\$ php -r \'echo \"hi!\\n\";\'

\$ ruby -e \'puts \"hi!\"\'

[]{#block-delimiters}[block delimiters](#block-delimiters-note)\
[ ]{style="white-space: pre-wrap;"}

{}

: [*and offside rule*]{style="color: gray"}

{}

{}\
do end

[]{#statement-separator}[statement
separator](#statement-separator-note)\
[ ]{style="white-space: pre-wrap;"}

[*; or newline\
\
newline not separator inside (), \[\], {}, \"\", \'\', or after binary
operator\
\
newline sometimes not separator when following line would not parse as a
valid statement*]{style="color: gray"}

[*newline or*]{style="color: gray"} ;\
\
[*newlines not separators inside (), \[\], {}, triple quote literals, or
after backslash:
[\\]{style="white-space: pre-wrap;"}*]{style="color: gray"}

;\
\
[*statements must be semicolon terminated inside
{}*]{style="color: gray"}

[*newline or*]{style="color: gray"} ;\
\
[*newlines not separators inside (), \[\], {},
[\`\`]{style="white-space: pre-wrap;"}, \'\', \"\", or after binary
operator or backslash:
[\\]{style="white-space: pre-wrap;"}*]{style="color: gray"}

[]{#source-code-encoding}[source code
encoding](#source-code-encoding-note)

[*source is always UTF-8*]{style="color: gray"}

[*Python 3 source is UTF-8 by default; Python 2 source is
US-ASCII*]{style="color: gray"}\
\
[\# -\*- coding: us-ascii -\*-]{style="color: gray"}

[*none*]{style="color: gray"}

[*Ruby 2.0 source is UTF-8 by default*]{style="color: gray"}\
\
[\# -\*- coding: utf-8 -\*-]{style="color: gray"}

[]{#eol-comment}[end-of-line comment](#eol-comment-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} comment]{style="color: gray"}

[\# comment]{style="color: gray"}

[[//]{style="white-space: pre-wrap;"} comment\
\# comment]{style="color: gray"}

[\# comment]{style="color: gray"}

[]{#multiple-line-comment}[multiple line
comment](#multiple-line-comment-note)\
[ ]{style="white-space: pre-wrap;"}

[/\* line\
another line \*/]{style="color: gray"}

[*use triple quote string literal:*]{style="color: gray"}\
\
\'\'\'comment line\
another line\'\'\'

[/\* comment line\
another line \*/]{style="color: gray"}

[=begin\
comment line\
another line\
=end]{style="color: gray"}

[]{#var-expr}[variables and expressions](#var-expr-note)

node.js

python

php

ruby

[]{#local-var}[local variable](#local-var-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} new in ES6:]{style="color: gray"}\
let x = 1;\
let y = 2, z = 3;\
\
[[//]{style="white-space: pre-wrap;"} older alternative to
let:]{style="color: gray"}\
var x = 1;\
\
[[//]{style="white-space: pre-wrap;"} let local scope is nearest\
[//]{style="white-space: pre-wrap;"} enclosing block; var local scope\
[//]{style="white-space: pre-wrap;"} is nearest function body.\
\
[//]{style="white-space: pre-wrap;"} var variables are visible to all
code\
[//]{style="white-space: pre-wrap;"} in the function body; even code\
[//]{style="white-space: pre-wrap;"} preceding the var
statement.]{style="color: gray"}

[\# in function body:]{style="color: gray"}\
x = 1\
y, z = 2, 3

[\# in function body:]{style="color: gray"}\
\$x = 1;\
list(\$y, \$z) = \[2, 3\];

x = 1\
y, z = 2, 3

[]{#file-scope-var}[file scope variable](#file-scope-var-note)

[[//]{style="white-space: pre-wrap;"} outside any function
body:]{style="color: gray"}\
let n = 1;\
\
incrFileVar () { n++; }

[*none*]{style="color: gray"}

[*none*]{style="color: gray"}

[*none*]{style="color: gray"}

[]{#global-var}[global variable](#global-var-note)

global.g = 1;\
\
incrGlobal () { global.g++; }

g = 1\
\
def incr\_global():\
[  ]{style="white-space: pre-wrap;"}global g\
[  ]{style="white-space: pre-wrap;"}g += 1

\$g = 1;\
\
function incr\_global() {\
[  ]{style="white-space: pre-wrap;"}global \$g;\
[  ]{style="white-space: pre-wrap;"}++\$g;\
}

\$g = 1\
\
def incr\_global\
[  ]{style="white-space: pre-wrap;"}\$g += 1\
end

[]{#const}[constant](#const-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} new in ES6]{style="color: gray"}\
const PI = 3.14;

[\# uppercase identifiers\
\# constant by convention]{style="color: gray"}\
PI = 3.14

define(\"PI\", 3.14);\
\
const PI = 3.14;

[\# warning if capitalized\
\# identifier is reassigned]{style="color: gray"}\
PI = 3.14

[]{#assignment}[assignment](#assignment-note)\
[ ]{style="white-space: pre-wrap;"}

v = 1;

[\# assignments can be chained\
\# but otherwise don\'t return values:]{style="color: gray"}\
v = 1

\$v = 1;

v = 1

[]{#parallel-assignment}[parallel
assignment](#parallel-assignment-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} new in ES6:]{style="color: gray"}\
let \[x, y, z\] = \[1, 2, 3\];

x, y, z = 1, 2, 3\
\
[\# raises ValueError:]{style="color: gray"}\
x, y = 1, 2, 3\
\
[\# raises ValueError:]{style="color: gray"}\
x, y, z = 1, 2

list(\$x, \$y, \$z) = \[1 ,2, 3\];\
\
[\# 3 is discarded:]{style="color: gray"}\
list(\$x, \$y) = \[1, 2, 3\];\
\
[\# \$z set to NULL:]{style="color: gray"}\
list(\$x, \$y, \$z) = \[1, 2\];

x, y, z = 1, 2, 3\
\
[\# 3 is discarded:]{style="color: gray"}\
x, y = 1, 2, 3\
\
[\# z set to nil:]{style="color: gray"}\
x, y, z = 1, 2

[]{#swap}[swap](#swap-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} new in ES6:]{style="color: gray"}\
\[x, y\] = \[y, x\];

x, y = y, x

list(\$x, \$y) = \[\$y, \$x\];

x, y = y, x

[]{#compound-assignment}[compound
assignment](#compound-assignment-note)\
[*arithmetic, string, logical, bit*]{style="color: gray"}

+= -= \*= /= [*none*]{style="color: gray"} %=\
+=\
[*none*]{style="color: gray"}\
[\<\<= \>\>= ]{style="white-space: pre-wrap;"}&= \|= \^=

[\# do not return values:]{style="color: gray"}\
+= -= \*= /= [//]{style="white-space: pre-wrap;"}= %=
[\*\*]{style="white-space: pre-wrap;"}=\
+= \*=\
&= [\|]{style="white-space: pre-wrap;"}= \^=\
[\<\<= \>\>= ]{style="white-space: pre-wrap;"}&= \|= \^=

+= -= \*= [*none*]{style="color: gray"} /= %=
[\*\*]{style="white-space: pre-wrap;"}=\
.= [*none*]{style="color: gray"}\
&= \|= [*none*]{style="color: gray"}\
[\<\<= \>\>= ]{style="white-space: pre-wrap;"}&= \|= \^=

+= -= \*= /= [*none*]{style="color: gray"} %=
[\*\*]{style="white-space: pre-wrap;"}=\
+= \*=\
&&= [\|\|]{style="white-space: pre-wrap;"}= \^=\
[\<\<= \>\>= ]{style="white-space: pre-wrap;"}&= \|= \^=

[]{#incr-decr}[increment and decrement](#incr-decr-note)\
[ ]{style="white-space: pre-wrap;"}

let x = 1;\
let y = ++x;\
let z = [\--]{style="white-space: pre-wrap;"}y;

[*none*]{style="color: gray"}

\$x = 1;\
\$y = ++\$x;\
\$z = [\--]{style="white-space: pre-wrap;"}\$y;

x = 1\
[\# x and y not mutated:]{style="color: gray"}\
y = x.succ\
z = y.pred

[]{#null}[null](#null-note)\
[ ]{style="white-space: pre-wrap;"}

null

None

NULL [\# case insensitive]{style="color: gray"}

nil

[]{#null-test}[null test](#null-test-note)\
[ ]{style="white-space: pre-wrap;"}

v === null

v is None

is\_null(\$v)\
! isset(\$v)

v == nil\
v.nil?

[]{#undef-var}[undefined variable](#undef-var-note)\
[ ]{style="white-space: pre-wrap;"}

[*Evaluates as*]{style="color: gray"} undefined\
\
[*Use the triple equality*]{style="color: gray"} === [*operator to test
for this value.*]{style="color: gray"}

[*raises*]{style="color: gray"} NameError

[*Evaluates as*]{style="color: gray"} NULL

[*raises*]{style="color: gray"} NameError

[]{#conditional-expr}[conditional expression](#conditional-expr-note)\
[ ]{style="white-space: pre-wrap;"}

x \> 0 ? x : -x

x if x \> 0 else -x

\$x \> 0 ? \$x : -\$x

x \> 0 ? x : -x

[]{#arithmetic-logic}[arithmetic and logic](#arithmetic-logic-note)

node.js

python

php

ruby

[]{#true-false}[true and false](#true-false-note)\
[ ]{style="white-space: pre-wrap;"}

true false

True False

TRUE FALSE [\# case insensitive]{style="color: gray"}

true false

[]{#falsehoods}[falsehoods](#falsehoods-note)\
[ ]{style="white-space: pre-wrap;"}

false null undefined \'\' 0 NaN

False None 0 0.0 \'\' \[\] {}

FALSE NULL 0 0.0 \"\" \"0\" \[\]

false nil

[]{#logical-op}[logical operators](#logical-op-note)\
[ ]{style="white-space: pre-wrap;"}

[&& \|\|]{style="white-space: pre-wrap;"} !

and or not

&& [\|\|]{style="white-space: pre-wrap;"} !\
[*lower precedence:*]{style="color: gray"}\
and or xor

&& [\|\|]{style="white-space: pre-wrap;"} !\
[*lower precedence:*]{style="color: gray"}\
and or not

[]{#relational-op}[relational operators](#relational-op-note)\
[ ]{style="white-space: pre-wrap;"}

[===]{style="white-space: pre-wrap;"} !== \< \> \>= \<=\
\
[*perform type coercion:*]{style="color: gray"}\
[==]{style="white-space: pre-wrap;"} !=

[*relational operators are chainable:*]{style="color: gray"}\
== != \> \< \>= \<=

== != [*or*]{style="color: gray"} \<\> \> \< \>= \<=\
[*no conversion:*]{style="color: gray"} === !==

== != \> \< \>= \<=

[]{#min-max}[min and max](#min-max-note)\
[ ]{style="white-space: pre-wrap;"}

Math.min(1, 2, 3)\
Math.max(1, 2, 3)\
\
Math.min.apply(Math, \[1, 2, 3\])\
Math.max.apply(Math, \[1, 2, 3\])

min(1, 2, 3)\
max(1, 2, 3)\
\
min(\[1, 2, 3\])\
max(\[1, 2, 3\])

min(1, 2, 3)\
max(1, 2, 3)\
\$a = \[1, 2, 3\]\
min(\$a)\
max(\$a)

\[1, 2, 3\].min\
\[1, 2, 3\].max

[]{#arith-op}[arithmetic operators](#arith-op-note)\
[*addition, subtraction, multiplication, float division, quotient,
remainder*]{style="color: gray"}

\+ - \* / [*none*]{style="color: gray"} %

\+ - \* / // %\
\
[*In Python 2, / performs integer division.*]{style="color: gray"}

\+ - \* / [*none*]{style="color: gray"} %

\+ - \* x.fdiv(y) / %

[]{#int-div}[integer division](#int-div-note)\
[ ]{style="white-space: pre-wrap;"}

Math.floor(22 / 7)

22 // 7

(int)(22 / 7)

22 / 7

[]{#divmod}[divmod](#divmod-note)\
[ ]{style="white-space: pre-wrap;"}

[*none*]{style="color: gray"}

q, r = divmod(22, 7)

[*none*]{style="color: gray"}

q, r = 22.divmod(7)

[]{#int-div-zero}[integer division by zero](#int-div-zero-note)\
[ ]{style="white-space: pre-wrap;"}

[*Returns Infinity, NaN, or -Infinity depending upon sign of dividend.\
\
There are literals for Infinity and NaN.*]{style="color: gray"}

[*raises* ZeroDivisionError]{style="color: gray"}

[*returns* FALSE *with warning*]{style="color: gray"}

[*raises* ZeroDivisionError]{style="color: gray"}

[]{#float-div}[float division](#float-div-note)\
[ ]{style="white-space: pre-wrap;"}

22 / 7

22 / 7\
\
[\# Python 2:]{style="color: gray"}\
float(22) / 7

22 / 7

22.to\_f / 7\
\
22.fdiv(7)

[]{#float-div-zero}[float division by zero](#float-div-zero-note)\
[ ]{style="white-space: pre-wrap;"}

[*same behavior as for integers*]{style="color: gray"}

[*raises* ZeroDivisionError]{style="color: gray"}

[*returns* FALSE *with warning*]{style="color: gray"}

[*returns* -Infinity, NaN, *or* Infinity]{style="color: gray"}

[]{#power}[power](#power-note)\
[ ]{style="white-space: pre-wrap;"}

Math.pow(2, 32)

2 [\*\*]{style="white-space: pre-wrap;"} 32

pow(2, 32)

2 [\*\*]{style="white-space: pre-wrap;"} 32

[]{#sqrt}[sqrt](#sqrt-note)

Math.sqrt(2)

import math\
\
math.sqrt(2)

sqrt(2)

include Math\
\
sqrt(2)

[]{#sqrt-negative-one}[sqrt -1](#sqrt-negative-one-note)\
[ ]{style="white-space: pre-wrap;"}

NaN

[\# raises ValueError:]{style="color: gray"}\
import math\
math.sqrt(-1)\
\
[\# returns complex float:]{style="color: gray"}\
import cmath\
cmath.sqrt(-1)

NaN

[Math.sqrt(-1) raises Math::DomainError unless require \'complex\' is in
effect.]{style="color: gray"}\
\
[(-1) \*\* 0.5 is (0+1.0i)]{style="color: gray"}

[]{#transcendental-func}[transcendental
functions](#transcendental-func-note)\
[ ]{style="white-space: pre-wrap;"}

Math.exp Math.log Math.sin Math.cos Math.tan Math.asin Math.acos
Math.atan Math.atan2

from math import exp, log, \\\
sin, cos, tan, asin, acos, atan, atan2

exp log sin cos tan asin acos atan atan2

include Math\
\
exp log sin cos tan asin acos atan atan2

[]{#transcendental-const}[transcendental
constants](#transcendental-const-note)\
[*π and e*]{style="color: gray"}

Math.PI\
Math.E

import math\
\
math.pi math.e

M\_PI M\_E

include Math\
\
PI E

[]{#float-truncation}[float truncation](#float-truncation-note)\
[ ]{style="white-space: pre-wrap;"}

[*none*]{style="color: gray"}\
Math.round(3.1)\
Math.floor(3.1)\
Math.ceil(3.1)

import math\
\
int(x)\
int(round(x))\
math.ceil(x)\
math.floor(x)

(int)\$x\
round(\$x)\
ceil(\$x)\
floor(\$x)

x.to\_i\
x.round\
x.ceil\
x.floor

[]{#abs-val}[absolute value](#abs-val-note)\
[ ]{style="white-space: pre-wrap;"}

Math.abs(-3)

abs(x)

abs(\$x)

x.abs

[]{#int-overflow}[integer overflow](#int-overflow-note)\
[ ]{style="white-space: pre-wrap;"}

[*all numbers are floats*]{style="color: gray"}

[*becomes arbitrary length integer of type* long]{style="color: gray"}

[*converted to float*]{style="color: gray"}

[*becomes arbitrary length integer of type* Bignum]{style="color: gray"}

[]{#float-overflow}[float overflow](#float-overflow-note)\
[ ]{style="white-space: pre-wrap;"}

Infinity

[*raises* OverflowError]{style="color: gray"}

INF

Infinity

[]{#rational-construction}[rational
construction](#rational-construction-note)\
[ ]{style="white-space: pre-wrap;"}

[*none*]{style="color: gray"}

from fractions import Fraction\
\
x = Fraction(22, 7)

[*none*]{style="color: gray"}

22 / 7r\
22r / 7

[]{#rational-decomposition}[rational
decomposition](#rational-decomposition-note)\
[ ]{style="white-space: pre-wrap;"}

[*none*]{style="color: gray"}

x.numerator\
x.denominator

[*none*]{style="color: gray"}

(22 / 7r).numerator\
(22 / 7r).denominator

[]{#complex-construction}[complex
construction](#complex-construction-note)\
[ ]{style="white-space: pre-wrap;"}

[*none*]{style="color: gray"}

z = 1 + 1.414j

[*none*]{style="color: gray"}

z = 1 + 1.414i

[]{#complex-decomposition}[complex
decomposition](#complex-decomposition-note)\
[*real and imaginary component, argument, absolute value,
conjugate*]{style="color: gray"}

[*none*]{style="color: gray"}

import cmath\
\
z.real\
z.imag\
cmath.phase(z)\
abs(z)\
z.conjugate()

[*none*]{style="color: gray"}

(1 + 3i).real\
(1 + 3i).imag\
(1 + 3i).arg\
(1 + 3i).abs\
(1 + 3i).conj

[]{#random-num}[random number](#random-num-note)\
[*uniform integer, uniform float, normal float*]{style="color: gray"}

Math.floor(Math.random() \* 100)\
Math.random()\
[*none*]{style="color: gray"}

import random\
\
random.randint(0, 99)\
random.random()\
random.gauss(0, 1)

rand(0,99)\
lcg\_value()\
[*none*]{style="color: gray"}

rand(100)\
rand\
[*none*]{style="color: gray"}

[]{#random-seed}[random seed](#random-seed-note)\
[*set, get, restore*]{style="color: gray"}

[*none*]{style="color: gray"}

import random\
\
random.seed(17)\
seed = random.getstate()\
random.setstate(seed)

srand(17);\
\
[*none*]{style="color: gray"}

srand(17)\
\
seed = srand\
srand(seed)

[]{#bit-op}[bit operators](#bit-op-note)\
[ ]{style="white-space: pre-wrap;"}

[\<\< \>\> & \| \^ \~]{style="white-space: pre-wrap;"}

[\<\< \>\> & \| \^ \~]{style="white-space: pre-wrap;"}

[\<\< \>\> & \| \^ \~]{style="white-space: pre-wrap;"}

[\<\< \>\> & \| \^ \~]{style="white-space: pre-wrap;"}

[]{#binary-octal-hex-literals}[binary, octal, and hex
literals](#binary-octal-hex-literals-note)

[*none*]{style="color: gray"}\
052 [[//]{style="white-space: pre-wrap;"}
deprecated]{style="color: gray"}\
0x2a

0b101010\
0o52[  ]{style="white-space: pre-wrap;"}[[\#]{style="white-space: pre-wrap;"}
also 052 in Python 2]{style="color: gray"}\
0x2a

0b101010\
052\
0x2a

0b101010\
052\
0x2a

[]{#radix}[radix](#radix-note)\
[*convert integer to and from string with radix*]{style="color: gray"}

(42).toString(7)\
parseInt(\'60\', 7)

[*none*]{style="color: gray"}\
int(\'60\', 7)

base\_convert(\"42\", 10, 7);\
base\_convert(\"60\", 7, 10);

42.to\_s(7)\
\"60\".to\_i(7)

[]{#strings}[strings](#strings-note)

node.js

python

php

ruby

[]{#str-type}[string type](#str-type-note)\
[ ]{style="white-space: pre-wrap;"}

String

str\
\
[\# Python 2:]{style="color: gray"}\
unicode

[\# array of bytes:]{style="color: gray"}\
string

String

[]{#str-literal}[string literal](#str-literal-note)\
[ ]{style="white-space: pre-wrap;"}

\'don\\\'t say \"no\"\'\
\"don\'t say \\\"no\\\"\"

\'don\\\'t say \"no\"\'\
\"don\'t say \\\"no\\\"\"\
\"don\'t \" \'say \"no\"\'\
\
[\# Python 2 (and Python 3):]{style="color: gray"}\
u\'lorem\'\
u\"ipsum\"

\"don\'t say \\\"no\\\"\"\
\'don\\\'t say \"no\"\'

\"don\'t say \\\"no\\\"\"\
\'don\\\'t say \"no\"\'\
\"don\'t \" \'say \"no\"\'

[]{#newline-in-str-literal}[newline in
literal](#newline-in-str-literal-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} backquote literals
only:]{style="color: gray"}\
[\`]{style="white-space: pre-wrap;"}first line\
second line[\`]{style="white-space: pre-wrap;"}\
\
[[//]{style="white-space: pre-wrap;"} Backslashes can be used to break\
[//]{style="white-space: pre-wrap;"} long strings.]{style="color: gray"}

[\# triple quote literals only:]{style="color: gray"}\
\'\'\'first line\
second line\'\'\'\
\
\"\"\"first line\
second line\"\"\"

\'first line\
second line\'\
\
\"first line\
second line\"

\'first line\
second line\'\
\
\"first line\
second line\"

[]{#str-literal-esc}[literal escapes](#str-literal-esc-note)\
[ ]{style="white-space: pre-wrap;"}

[*single and double quotes:*]{style="color: gray"}\
\\b \\f \\n \\r \\t \\v \\x[*hh*]{style="color: gray"} \\\" \\\' \\\\\
\\u[*hhhh*]{style="color: gray"} \\u{[*hhhhh*]{style="color: gray"}}

\\[*newline*]{style="color: gray"} \\\\ \\\' \\\" \\a \\b \\f \\n \\r
\\t \\v \\[*ooo*]{style="color: gray"} \\x[*hh*]{style="color: gray"}
\\u[*hhhh*]{style="color: gray"} \\U[*hhhhhhhh*]{style="color: gray"}\
\
[*In Python 2,* \\u *and* \\U *only available in string literals with* u
*prefix*]{style="color: gray"}

[*double quoted:*]{style="color: gray"}\
\\f \\n \\r \\t \\v \\x[*hh*]{style="color: gray"} \\\$ \\\" \\\\
\\[*ooo*]{style="color: gray"}\
\
[*single quoted:*]{style="color: gray"}\
\\\' \\\\

[*double quoted:*]{style="color: gray"}\
\\a \\b \\c[*x*]{style="color: gray"} \\e \\f \\n \\r \\s \\t \\v
\\x[*hh*]{style="color: gray"} \\[*ooo*]{style="color: gray"}
\\u[*hhhh*]{style="color: gray"} \\u{[*hhhhh*]{style="color: gray"}}\
\
[*single quoted:*]{style="color: gray"}\
\\\' \\\\

[]{#here-doc}[here document](#here-doc-note)\
[ ]{style="white-space: pre-wrap;"}

[*none*]{style="color: gray"}

[*none*]{style="color: gray"}

\$word = \"amet\";\
\
\$s = [\<\<\<]{style="white-space: pre-wrap;"}EOF\
lorem ipsum\
dolor sit \$word\
EOF;

word = \"amet\"\
\
s = [\<\<]{style="white-space: pre-wrap;"}EOF\
lorem ipsum\
dolor sit \#{word}\
EOF

[]{#var-interpolation}[variable interpolation](#var-interpolation-note)\
[ ]{style="white-space: pre-wrap;"}

let count = 3;\
let item = \'ball\';\
let s = [\`]{style="white-space: pre-wrap;"}\${count}
\${item}s[\`]{style="white-space: pre-wrap;"};

count = 3\
item = \'ball\'\
print(\'{count} {item}s\'.format(\
[  ]{style="white-space: pre-wrap;"}[\*\*]{style="white-space: pre-wrap;"}locals()))\
\
[\# Python 3.6:]{style="color: gray"}\
print(f\'{count} {item}s\')

\$count = 3;\
\$item = \"ball\";\
echo \"\$count \${item}s\\n\";

count = 3\
item = \"ball\"\
puts \"\#{count} \#{item}s\"

[]{#expr-interpolation}[expression
interpolation](#expr-interpolation-note)

[\`]{style="white-space: pre-wrap;"}1 + 1 = \${1 +
1}[\`]{style="white-space: pre-wrap;"}

\'1 + 1 = {}\'.format(1 + 1)\
\
[\# Python 3.6:]{style="color: gray"}\
f\'1 + 1 = {1 + 1}\'

[*none*]{style="color: gray"}

\"1 + 1 = \#{1 + 1}\"

[]{#format-str}[format string](#format-str-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} None; use string concatenation.\
[//]{style="white-space: pre-wrap;"} Evaluates to
\"12.35\":]{style="color: gray"}\
12.3456.toFixed(2)

\'lorem %s %d %f\' % (\'ipsum\', 13, 3.7)\
\
fmt = \'lorem {0} {1} {2}\'\
fmt.format(\'ipsum\', 13, 3.7)

\$fmt = \"lorem %s %d %f\";\
sprintf(\$fmt, \"ipsum\", 13, 3.7);

\"lorem %s %d %f\" % \[\"ipsum\", 13, 3.7\]

[]{#mutable-str}[are strings mutable?](#mutable-str-note)

[*no*]{style="color: gray"}

[*no*]{style="color: gray"}

\$s = \"bar\";\
\$s2 = \$s;\
[\# sets s to \"baz\"; s2 is unchanged:]{style="color: gray"}\
\$s\[2\] = \"z\";

s = \"bar\"\
s2 = s\
[\# sets s and s2 to \"baz\":]{style="color: gray"}\
s\[2\] = \"z\"

[]{#copy-str}[copy string](#copy-str-note)

[*none*]{style="color: gray"}

[*none*]{style="color: gray"}

\$s2 = \$s;

s = \"bar\"\
s2 = s.clone\
[\# s2 is not altered:]{style="color: gray"}\
s\[2\] = \"z\"

[]{#str-concat}[concatenate](#str-concat-note)\
[ ]{style="white-space: pre-wrap;"}

s = \'Hello, \' + \'World!\';

s = \'Hello, \'\
s2 = s + \'World!\'\
\
[\# juxtaposition can be used to\
\# concatenate literals:]{style="color: gray"}\
s2 = \'Hello, \' \"World!\"

\$s = \"Hello, \";\
\$s2 = \$s . \"World!\";

s = \"Hello, \"\
s2 = s + \"World!\"\
\
[\# juxtaposition can be used to\
\# concatenate literals:]{style="color: gray"}\
s2 = \"Hello, \" \'World!\'

[]{#str-replicate}[replicate](#str-replicate-note)\
[ ]{style="white-space: pre-wrap;"}

let hbar = \_.repeat(\'-\', 80);

hbar = \'-\' \* 80

\$hbar = str\_repeat(\"-\", 80);

hbar = \"-\" \* 80

[]{#translate-case}[translate case](#translate-case-note)\
[*to upper, to lower*]{style="color: gray"}

\'lorem\'.toUpperCase()\
\'LOREM\'.toLowerCase()

\'lorem\'.upper()\
\'LOREM\'.lower()

mb\_strtoupper(\"lorem\")\
mb\_strtolower(\"LOREM\")\
[\# strtoupper/strtolower are ASCII only]{style="color: gray"}

\"lorem\".upcase\
\"LOREM\".downcase

[]{#capitalize}[capitalize](#capitalize-note)\
[*string, words*]{style="color: gray"}

\_.capitalize(\'lorem\');\
[*none*]{style="color: gray"}

import string\
\
\'lorem\'.capitalize()\
string.capwords(\'lorem ipsum\')

[\# ASCII only:]{style="color: gray"}\
ucfirst(strtolower(\"lorem\"))\
ucwords(strtolower(\"lorem ipsum\"))\
[\# Unicode title case:]{style="color: gray"}\
mb\_convert\_case(\"lorem ipsum\", MB\_CASE\_TITLE)

\"lorem\".capitalize\
[*none*]{style="color: gray"}

[]{#trim}[trim](#trim-note)\
[*both sides, left, right*]{style="color: gray"}

\' lorem \'.trim()\
\' lorem\'.trimLeft()\
\'lorem \'.trimRight()

\' lorem \'.strip()\
\' lorem\'.lstrip()\
\'lorem \'.rstrip()

trim(\" lorem \")\
ltrim(\" lorem\")\
rtrim(\"lorem \")

\" lorem \".strip\
\" lorem\".lstrip\
\"lorem \".rstrip

[]{#pad}[pad](#pad-note)\
[*on right, on left, centered*]{style="color: gray"}

\_.padStart(\'lorem\', 10)\
\_.padEnd(\'lorem\', 10)\
\_.pad(\'lorem\', 10)

\'lorem\'.ljust(10)\
\'lorem\'.rjust(10)\
\'lorem\'.center(10)

\$s = \"lorem\";\
\$delta = strlen(\$s) - mb\_strlen(\$s);\
str\_pad(\$s, 10 + \$delta)\
str\_pad(\"\$s, 10 + \$delta, \" \", STR\_PAD\_LEFT)\
str\_pad(\$s, 10 + \$delta, \" \", STR\_PAD\_BOTH)

\"lorem\".ljust(10)\
\"lorem\".rjust(10)\
\"lorem\".center(10)

[]{#num-to-str}[number to string](#num-to-str-note)\
[ ]{style="white-space: pre-wrap;"}

\'value: \' + 8

\'value: \' + str(8)

\"value: \" . 8

\"value: \" + 8.to\_s

[]{#fmt-float}[format float](#fmt-float-note)

\'\' + Math.round(Math.PI \* 100) / 100

import math\
\
\'%.2f\' % math.pi\
\'{:.3}\'.format(math.pi)\
[\# Python 3.6:]{style="color: gray"}\
f\'{math.pi:.{3}}\'

number\_format(M\_PI, 2)

include Math\
\
\'%.2f\' % PI\
\"\#{PI.round(2)}\"

[]{#str-to-num}[string to number](#str-to-num-note)\
[ ]{style="white-space: pre-wrap;"}

7 + parseInt(\'12;, 10)\
73.9 + parseFloat(\'.037\')\
\
[[//]{style="white-space: pre-wrap;"} 12:]{style="color: gray"}\
parseInt(\'12A\')\
[[//]{style="white-space: pre-wrap;"} NaN:]{style="color: gray"}\
parseInt(\'A\')

7 + int(\'12\')\
73.9 + float(\'.037\')\
\
[\# raises ValueError:]{style="color: gray"}\
int(\'12A\')\
[\# raises ValueError:]{style="color: gray"}\
int(\'A\')

7 + \"12\"\
73.9 + \".037\"\
\
[\# 12:]{style="color: gray"}\
0 + \"12A\"\
[\# 0:]{style="color: gray"}\
0 + \"A\"

7 + \"12\".to\_i\
73.9 + \".037\".to\_f\
\
[\# 12:]{style="color: gray"}\
\"12A\".to\_i\
[\# 0:]{style="color: gray"}\
\"A\".to\_i

[]{#str-join}[string join](#str-join-note)\
[ ]{style="white-space: pre-wrap;"}

\[\'do\', \'re\', \'mi\'\].join(\' \')

\' \'.join(\[\'do\', \'re\', \'mi\', \'fa\'\])\
\
[\# raises TypeError:]{style="color: gray"}\
\' \'.join(\[1, 2, 3\])

\$a = \[\"do\", \"re\", \"mi\", \"fa\"\];\
implode(\" \", \$a)

\%w(do re mi fa).join(\' \')\
\
[\# implicitly converted to strings:]{style="color: gray"}\
\[1, 2, 3\].join(\' \')

[]{#split}[split](#split-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} \[ \'do\', \'re\', \'\', \'mi\',
\'\' \]:]{style="color: gray"}\
\'do re[  ]{style="white-space: pre-wrap;"}mi \'.split(\' \')\
\
[[//]{style="white-space: pre-wrap;"} \[ \'do\', \'re\', \'mi\', \'\'
\]:]{style="color: gray"}\
\'do re[  ]{style="white-space: pre-wrap;"}mi \'.split(/\\s+/)

[\# \[\'do\', \'re\', \'\', \'mi\', \'\'\]:]{style="color: gray"}\
\'do re[  ]{style="white-space: pre-wrap;"}mi \'.split(\' \')\
\
[\# \[\'do\', \'re\', \'mi\'\]:]{style="color: gray"}\
\'do re[  ]{style="white-space: pre-wrap;"}mi \'.split()

[\# \[ \"do\", \"re\", \"\", \"mi\", \"\" \]:]{style="color: gray"}\
explode(\" \", \"do re[  ]{style="white-space: pre-wrap;"}mi \")\
\
[\# \[ \"do\", \"re\", \"mi\", \"\" \]:]{style="color: gray"}\
preg\_split(\'/\\s+/\', \"do re[  ]{style="white-space: pre-wrap;"}mi
\")

[\# \[\"do\", \"re\", \"\", \"mi\"\]:]{style="color: gray"}\
\"do re[  ]{style="white-space: pre-wrap;"}mi \".split(/ /)\
\
[\# \[\"do\", \"re\", \"mi\"\]:]{style="color: gray"}\
\"do re[  ]{style="white-space: pre-wrap;"}mi \".split

[]{#split-in-two}[split in two](#split-in-two-note)\
[ ]{style="white-space: pre-wrap;"}

\'do re mi fa\'.split(/\\s+/, 2)

\'do re mi fa\'.split(None, 1)

preg\_split(\'/\\s+/\', \"do re mi fa\", 2)

\"do re mi fa\".split(/\\s+/, 2)

[]{#split-keep-delimiters}[split and keep
delimiters](#split-keep-delimiters-note)

[*none*]{style="color: gray"}

re.split(\'(\\s+)\', \'do re mi fa\')

preg\_split(\'/(\\s+)/\', \"do re mi fa\",\
[  ]{style="white-space: pre-wrap;"}NULL, PREG\_SPLIT\_DELIM\_CAPTURE)

\"do re mi fa\".split(/(\\s+)/)

[]{#prefix-suffix-test}[prefix and suffix
test](#prefix-suffix-test-note)

\'foobar\'.startsWith(\'foo\')\
\'foobar\'.endsWith(\'bar\')

\'foobar\'.startswith(\'foo\')\
\'foobar\'.endswith(\'bar\')

\'foobar\'.start\_with?(\'foo\')\
\'foobar\'.end\_with?(\'bar\')

[]{#str-len}[length](#str-len-note)\
[ ]{style="white-space: pre-wrap;"}

\'lorem\'.length

len(\'lorem\')

mb\_strlen(\"lorem\")\
[\# strlen() counts bytes]{style="color: gray"}

\"lorem\".length\
\"lorem\".size

[]{#index-substr}[index of substring](#index-substr-note)\
[*first, last*]{style="color: gray"}

[[//]{style="white-space: pre-wrap;"} returns -1 if not
found:]{style="color: gray"}\
\'lorem ipsum\'.indexOf(\'ipsum\')

[\# raises ValueError if not found:]{style="color: gray"}\
\'do re re\'.index(\'re\')\
\'do re re\'.rindex(\'re\')\
\
[\# returns -1 if not found:]{style="color: gray"}\
\'do re re\'.find(\'re\')\
\'do re re\'.rfind(\'re\')

[\# returns FALSE if not found:]{style="color: gray"}\
mb\_strpos(\"do re re\", \"re\")\
mb\_strrpos(\"do re re\", \"re\")

[\# returns nil if not found:]{style="color: gray"}\
\"do re re\".index(\"re\")\
\"do re re\".rindex(\"re\")

[]{#extract-substr}[extract substring](#extract-substr-note)\
[*by start and length, by start and end, by successive
starts*]{style="color: gray"}

\'lorem ipsum\'.substr(6, 5)\
\'lorem ipsum\'.substring(6, 11)

[*none*]{style="color: gray"}\
[*none*]{style="color: gray"}\
\'lorem ipsum\'\[6:11\]

mb\_substr(\"lorem ipsum\", 6, 5)\
[*none*]{style="color: gray"}\
[*none*]{style="color: gray"}

\"lorem ipsum\"\[6, 5\]\
\"lorem ipsum\"\[6[..]{style="white-space: pre-wrap;"}10\]\
\"lorem ipsum\"\[6[\...]{style="white-space: pre-wrap;"}11\]

[]{#bytes-type}[byte array type](#bytes-type-note)

Buffer

bytes\
\
[\# In Python 2, str also byte array type]{style="color: gray"}

string

Array [*of*]{style="color: gray"} Fixnum

[]{#bytes-to-str}[byte array to string](#bytes-to-str-note)

let a = Buffer.from(\[0xce, 0xbb\]);\
let s = a.toString(\'utf-8\');

s = b\'\\xce\\xbb\'.decode(\'utf-8\')

[*strings are byte arrays*]{style="color: gray"}

a = \"\\u03bb\".bytes\
s = a.pack(\"C\*\").force\_encoding(\'utf-8\')

[]{#str-to-bytes}[string to byte array](#str-to-bytes-note)

a = Buffer.from(\'\\u03bb\')

a = \'\\u03bb\'.encode(\'utf-8\')\
\
[\# Python 2:]{style="color: gray"}\
a = u\'\\u03bb\'.encode(\'utf-8\')

[*strings are byte arrays*]{style="color: gray"}

a = \"\\u03bb\".bytes

[]{#lookup-char}[character lookup](#lookup-char-note)

\'lorem ipsum\'\[6\]

\'lorem ipsum\'\[6\]

mb\_substr(\"lorem ipsum\", 6, 1)\
[\# byte lookup:]{style="color: gray"}\
\"lorem ipsum\"\[6\]

\"lorem ipsum\"\[6\]

[]{#chr-ord}[chr and ord](#chr-ord-note)\
[ ]{style="white-space: pre-wrap;"}

String.fromCharCode(65)\
\'A\'.charCodeAt(0)

chr(65)\
ord(\'A\')

[\# ASCII only:]{style="color: gray"}\
chr(65)\
ord(\"A\")

65.chr(\'UTF-8\')\
\"A\".ord

[]{#str-to-char-array}[to array of characters](#str-to-char-array-note)\
[ ]{style="white-space: pre-wrap;"}

\'abcd\'.split(\'\')

list(\'abcd\')

str\_split(\"abcd\")

\"abcd\".split(\"\")

[]{#translate-char}[translate characters](#translate-char-note)\
[ ]{style="white-space: pre-wrap;"}

[*none*]{style="color: gray"}

from string import ascii\_lowercase\
\
ins = ascii\_lowercase\
outs = ins\[13:\] + ins\[:13\]\
table = str.maketrans(ins, outs)\
\'hello\'.translate(table)

\$ins = implode(range(\"a\", \"z\"));\
\$outs = substr(\$ins, 13, 13) .\
[  ]{style="white-space: pre-wrap;"}substr(\$ins, 0, 13);\
strtr(\"hello\", \$ins, \$outs)

\"hello\".tr(\"a-z\", \"n-za-m\")

[]{#delete-char}[delete characters](#delete-char-note)

[*none*]{style="color: gray"}

table = {ord(ch): None for ch in \"aeiou\"}\
\"disemvowel me\".translate(table)

\$vowels = str\_split(\"aeiou\");\
\$s = \"disemvowel me\";\
\$s = str\_replace(\$vowels, \"\", \$s);

\"disemvowel me\".delete(\"aeiou\")

[]{#squeeze-char}[squeeze characters](#squeeze-char-note)

[*none*]{style="color: gray"}

re.sub(\'(\\s)+\', r\'\\1\',\
[  ]{style="white-space: pre-wrap;"}\'too[   ]{style="white-space: pre-wrap;"}much[   ]{style="white-space: pre-wrap;"}space\')

\$s =
\"too[   ]{style="white-space: pre-wrap;"}much[   ]{style="white-space: pre-wrap;"}space\";\
\$s = = preg\_replace(\'/(\\s)+/\', \'\\1\', \$s);

\"too[   ]{style="white-space: pre-wrap;"}much[   ]{style="white-space: pre-wrap;"}space\".squeeze(\"
\")

[]{#regexes}[regular expressions](#regexes-note)

node.js

python

php

ruby

[]{#regex-literal}[literal, custom delimited
literal](#regex-literal-note)

/lorem\|ipsum/

re.compile(r\'lorem\|ipsum\')\
[*none*]{style="color: gray"}

\'/lorem\|ipsum/\'\
\'(/etc/hosts)\'

/lorem\|ipsum/\
%r(/etc/hosts)\
[\# double quoted string escapes\
\# and \#{} substitution can be used]{style="color: gray"}

[]{#ascii-char-class-abbrev}[ascii character class
abbreviations](#ascii-char-class-abbrev-note)

.[   ]{style="white-space: pre-wrap;"}\[\^\\n\]\
\\d[  ]{style="white-space: pre-wrap;"}\[0-9\]\
\\D[  ]{style="white-space: pre-wrap;"}\[\^0-9\]\
\\s[  ]{style="white-space: pre-wrap;"}\[ \\t\\r\\n\\f\]\
\\S[  ]{style="white-space: pre-wrap;"}\[\^ \\t\\r\\n\\f\]\
\\w[  ]{style="white-space: pre-wrap;"}\[A-Za-z0-9\_\]\
\\W[  ]{style="white-space: pre-wrap;"}\[\^A-Za-z0-9\_\]

.[   ]{style="white-space: pre-wrap;"}\[\^\\n\][  ]{style="white-space: pre-wrap;"}[*with*
re.S *modifier matches all chars*]{style="color: gray"}\
\\d[  ]{style="white-space: pre-wrap;"}\[0-9\]\
\\D[  ]{style="white-space: pre-wrap;"}\[\^0-9\]\
\\s[  ]{style="white-space: pre-wrap;"}\[ \\t\\r\\n\\f\]\
\\S[  ]{style="white-space: pre-wrap;"}\[\^ \\t\\r\\n\\f\]\
\\w[  ]{style="white-space: pre-wrap;"}\[A-Za-z0-9\_\]\
\\W[  ]{style="white-space: pre-wrap;"}\[\^A-Za-z0-9\_\]\
\
[*In Python 3, the above definitions are used when* re.A *is in
effect.*]{style="color: gray"}

.[   ]{style="white-space: pre-wrap;"}\[\^\\n\]\
\\d[  ]{style="white-space: pre-wrap;"}\[0-9\]\
\\D[  ]{style="white-space: pre-wrap;"}\[\^0-9\]\
\\h[  ]{style="white-space: pre-wrap;"}\[ \\t\]\
\\H[  ]{style="white-space: pre-wrap;"}\[\^ \\t\]\
\\s[  ]{style="white-space: pre-wrap;"}\[ \\t\\r\\n\\f\]\
\\S[  ]{style="white-space: pre-wrap;"}\[\^ \\t\\r\\n\\f\]\
\\w[  ]{style="white-space: pre-wrap;"}\[A-Za-z0-9\_\]\
\\W[  ]{style="white-space: pre-wrap;"}\[\^A-Za-z0-9\_\]

.[   ]{style="white-space: pre-wrap;"}\[\^\\n\][  ]{style="white-space: pre-wrap;"}[*with*
m *modifier matches all chars*]{style="color: gray"}\
\\d[  ]{style="white-space: pre-wrap;"}\[0-9\]\
\\D[  ]{style="white-space: pre-wrap;"}\[\^0-9\]\
\\h[  ]{style="white-space: pre-wrap;"}\[0-9a-fA-F\]\
\\H[  ]{style="white-space: pre-wrap;"}\[\^0-9a-fA-F\]\
\\s[  ]{style="white-space: pre-wrap;"}\[ \\t\\r\\n\\f\]\
\\S[  ]{style="white-space: pre-wrap;"}\[\^ \\t\\r\\n\\f\]\
\\w[  ]{style="white-space: pre-wrap;"}\[A-Za-z0-9\_\]\
\\W[  ]{style="white-space: pre-wrap;"}\[\^A-Za-z0-9\_\]

[]{#unicode-char-class-abbrev}[unicode character class
abbreviations](#unicode-char-class-abbrev-note)

[*none*]{style="color: gray"}

.[   ]{style="white-space: pre-wrap;"}\[\^\\n\][  ]{style="white-space: pre-wrap;"}[*with*
re.S *modifier matches all chars*]{style="color: gray"}\
\\d[  ]{style="white-space: pre-wrap;"}\[[*Nd*]{style="color: gray"}\][  ]{style="white-space: pre-wrap;"}[Nd:
*Number, decimal digit*]{style="color: gray"}\
\\D[  ]{style="white-space: pre-wrap;"}\[\^[*Nd*]{style="color: gray"}\]\
\\s[  ]{style="white-space: pre-wrap;"}\[[*Z*]{style="color: gray"}\\t\\n\\r\\f\\v\\x1c\\x1d\\x1e\\x1f\\x85\]\
\\S[  ]{style="white-space: pre-wrap;"}\[\^[*Z*]{style="color: gray"}\\t\\n\\r\\f\\v\\x1c\\x1d\\x1e\\x1f\\x85\]\
\\w
\[[*LN*]{style="color: gray"}\_\][  ]{style="white-space: pre-wrap;"}[L:
*Letter*; N: *Number*]{style="color: gray"}\
\\W \[[\^*LN*]{style="color: gray"}\_\]\
\
[*In Python 2, the above definitions are used when* re.U *is in
effect.*]{style="color: gray"}

[*POSIX character classes such as* \[\[:alpha:\]\] *are available, but
they match sets of ASCII characters. General category values (e.g.*
\\p{L}, \\p{Lu}*) can be used. Morever, they can be used inside
character classes (.e.g.* \[\\p{L}\\p{N}\]*).*]{style="color: gray"}

.\
\\p{Digit}\
\\p{\^Digit}\
\\p{Space}\
\\p{\^Space}\
\\p{Word}\
\\p{\^Word}\
\
[*POSIX character classes (e.g.*
[\[\[:alpha:\]\]]{style="white-space: pre-wrap;"}*), general category
values (e.g.* \\p{L}, \\p{Lu}*), and script names (e.g.* \\p{Greek})
*also supported.*]{style="color: gray"}

[]{#regex-anchors}[anchors](#regex-anchors-note)\
[ ]{style="white-space: pre-wrap;"}

\^[   ]{style="white-space: pre-wrap;"}[*start of string or line with* m
*modifier*]{style="color: gray"}\
\$[   ]{style="white-space: pre-wrap;"}[*end of string or line with* m
*modifier*]{style="color: gray"}\
\\b[  ]{style="white-space: pre-wrap;"}[*word boundary:* \\w\\W *or*
\\W\\w]{style="color: gray"}\
\\B[  ]{style="white-space: pre-wrap;"}[*non word
boundary*]{style="color: gray"}

\^[   ]{style="white-space: pre-wrap;"}[*start of string or line with*
re.M]{style="color: gray"}\
\$[   ]{style="white-space: pre-wrap;"}[*end of string or line with*
re.M]{style="color: gray"}\
\\A[  ]{style="white-space: pre-wrap;"}[*start of
string*]{style="color: gray"}\
\\b[  ]{style="white-space: pre-wrap;"}[*word boundary:* \\w\\W *or*
\\W\\w]{style="color: gray"}\
\\B[  ]{style="white-space: pre-wrap;"}[*non word
boundary*]{style="color: gray"}\
\\Z[  ]{style="white-space: pre-wrap;"}[*end of
string*]{style="color: gray"}

\^[   ]{style="white-space: pre-wrap;"}[*start of string or line with* m
*modifier*]{style="color: gray"}\
\$[   ]{style="white-space: pre-wrap;"}[*end of string or line with* m
*modifier*]{style="color: gray"}\
\\A[  ]{style="white-space: pre-wrap;"}[*start of
string*]{style="color: gray"}\
\\b[  ]{style="white-space: pre-wrap;"}[*word boundary:* \\w\\W *or*
\\W\\w]{style="color: gray"}\
\\B[  ]{style="white-space: pre-wrap;"}[*non word
boundary*]{style="color: gray"}\
\\z[  ]{style="white-space: pre-wrap;"}[*end of
string*]{style="color: gray"}\
\\Z[  ]{style="white-space: pre-wrap;"}[*end of string, excluding final
newline*]{style="color: gray"}

\^[   ]{style="white-space: pre-wrap;"}[*start of
line*]{style="color: gray"}\
\$[   ]{style="white-space: pre-wrap;"}[*end of
line*]{style="color: gray"}\
\\A[  ]{style="white-space: pre-wrap;"}[*start of
string*]{style="color: gray"}\
\\b[  ]{style="white-space: pre-wrap;"}[*unicode-aware word
boundary*]{style="color: gray"}\
\\B[  ]{style="white-space: pre-wrap;"}[*unicode-aware non word
boundary*]{style="color: gray"}\
\\z[  ]{style="white-space: pre-wrap;"}[*end of
string*]{style="color: gray"}\
\\Z[  ]{style="white-space: pre-wrap;"}[*end of string, excluding final
newline*]{style="color: gray"}

[]{#regex-test}[match test](#regex-test-note)\
[ ]{style="white-space: pre-wrap;"}

if (s.match(/1999/)) {\
[  ]{style="white-space: pre-wrap;"}console.log(\'party!\');\
}

if re.search(\'1999\', s):\
[  ]{style="white-space: pre-wrap;"}print(\'party!\')

if (preg\_match(\'/1999/\', \$s)) {\
[  ]{style="white-space: pre-wrap;"}echo \"party!\\n\";\
}

if /1999/.match(s)\
[  ]{style="white-space: pre-wrap;"}puts \"party!\"\
end

[]{#case-insensitive-regex}[case insensitive match
test](#case-insensitive-regex-note)\
[ ]{style="white-space: pre-wrap;"}

\'Lorem\'.match(/lorem/i)

re.search(\'lorem\', \'Lorem\', re.I)

preg\_match(\'/lorem/i\', \"Lorem\")

/lorem/i.match(\"Lorem\")

[]{#regex-modifiers}[modifiers](#regex-modifiers-note)\
[ ]{style="white-space: pre-wrap;"}

g[  ]{style="white-space: pre-wrap;"}[*used for global substitution and
scanning*]{style="color: gray"}\
i[  ]{style="white-space: pre-wrap;"}[*make case
insensitive*]{style="color: gray"}\
m[  ]{style="white-space: pre-wrap;"}[*change meaning of* \^ *and*
\$]{style="color: gray"}\
u[  ]{style="white-space: pre-wrap;"}[\\u{} *syntax and astral character
support*]{style="color: gray"}\
y[  ]{style="white-space: pre-wrap;"}[*used to scan in
loop*]{style="color: gray"}

re.A[  ]{style="white-space: pre-wrap;"}[*change meaning of* \\b \\B \\d
\\D \\s \\S \\w \\W]{style="color: gray"}\
re.I[  ]{style="white-space: pre-wrap;"}[*make case
insensitive*]{style="color: gray"}\
re.M[  ]{style="white-space: pre-wrap;"}[*change meaning of* \^ *and*
\$]{style="color: gray"}\
re.S[  ]{style="white-space: pre-wrap;"}[*change meaning of*
.]{style="color: gray"}\
re.X[  ]{style="white-space: pre-wrap;"}[*ignore whitespace outside char
class*]{style="color: gray"}

i[  ]{style="white-space: pre-wrap;"}[*make case
insensitive*]{style="color: gray"}\
m[  ]{style="white-space: pre-wrap;"}[*change meaning of* \^ *and*
\$]{style="color: gray"}\
s[  ]{style="white-space: pre-wrap;"}[*change meaning of*
.]{style="color: gray"}\
x[  ]{style="white-space: pre-wrap;"}[*ignore whitespace outside char
class*]{style="color: gray"}

i[  ]{style="white-space: pre-wrap;"}[*make case
insensitive*]{style="color: gray"}\
o[  ]{style="white-space: pre-wrap;"}[*interpolate \#{} in literal
once*]{style="color: gray"}\
m[  ]{style="white-space: pre-wrap;"}[*change meaning of*
.]{style="color: gray"}\
x[  ]{style="white-space: pre-wrap;"}[*ignore whitespace outside char
class*]{style="color: gray"}

[]{#subst}[substitution](#subst-note)\
[ ]{style="white-space: pre-wrap;"}

s = \'do re mi mi mi\';\
s.replace(/mi/g, \'ma\');

s = \'do re mi mi mi\'\
s = re.compile(\'mi\').sub(\'ma\', s)

\$s = \"do re mi mi mi\";\
\$s = preg\_replace(\'/mi/\', \"ma\", \$s);

s = \"do re mi mi mi\"\
s.gsub!(/mi/, \"ma\")

[]{#match-prematch-postmatch}[match, prematch,
postmatch](#match-prematch-postmatch-note)\
[ ]{style="white-space: pre-wrap;"}

m = /\\d{4}/.exec(s);\
if (m) {\
[  ]{style="white-space: pre-wrap;"}match = m\[0\];\
[  ]{style="white-space: pre-wrap;"}[[//]{style="white-space: pre-wrap;"}
no prematch or postmatch]{style="color: gray"}\
}

m = re.search(\'\\d{4}\', s)\
if m:\
[  ]{style="white-space: pre-wrap;"}match = m.group()\
[  ]{style="white-space: pre-wrap;"}prematch = s\[0:m.start(0)\]\
[  ]{style="white-space: pre-wrap;"}postmatch = s\[m.end(0):len(s)\]

[*none*]{style="color: gray"}

m = /\\d{4}/.match(s)\
if m\
[  ]{style="white-space: pre-wrap;"}match = m\[0\]\
[  ]{style="white-space: pre-wrap;"}prematch = m.pre\_match\
[  ]{style="white-space: pre-wrap;"}postmatch = m.post\_match\
end

[]{#group-capture}[group capture](#group-capture-note)\
[ ]{style="white-space: pre-wrap;"}

rx = /\^(\\d{4})-(\\d{2})-(\\d{2})\$/;\
m = rx.exec(\'2009-06-03\');\
yr = m\[1\];\
mo = m\[2\];\
dy = m\[3\];

rx = \'(\\d{4})-(\\d{2})-(\\d{2})\'\
m = re.search(rx, \'2010-06-03\')\
yr, mo, dy = m.groups()

\$s = \"2010-06-03\";\
\$rx = \'/(\\d{4})-(\\d{2})-(\\d{2})/\';\
preg\_match(\$rx, \$s, \$m);\
list(\$\_, \$yr, \$mo, \$dy) = \$m;

rx = /(\\d{4})-(\\d{2})-(\\d{2})/\
m = rx.match(\"2010-06-03\")\
yr, mo, dy = m\[1..3\]

[]{#named-group-capture}[named group capture](#named-group-capture-note)

[*none*]{style="color: gray"}

rx = \'\^(?P\<file\>.+)\\.(?P\<suffix\>.+)\$\'\
m = re.search(rx, \'foo.txt\')\
\
m.groupdict()\[\'file\'\]\
m.groupdict()\[\'suffix\'\]

\$s = \"foo.txt\";\
\$rx = \'/\^(?P\<file\>.+)\\.(?P\<suffix\>.+)\$/\';\
preg\_match(\$rx, \$s, \$m);\
\
\$m\[\"file\"\]\
\$m\[\"suffix\"\]

rx = /\^(?\<file\>.+)\\.(?\<suffix\>.+)\$/\
m = rx.match(\'foo.txt\')\
\
m\[\"file\"\]\
m\[\"suffix\"\]

[]{#scan}[scan](#scan-note)\
[ ]{style="white-space: pre-wrap;"}

let a = \'dolor sit amet\'.match(/\\w+/g);

s = \'dolor sit amet\'\
a = re.findall(\'\\w+\', s)

\$s = \"dolor sit amet\";\
preg\_match\_all(\'/\\w+/\', \$s, \$m);\
\$a = \$m\[0\];

a = \"dolor sit amet\".scan(/\\w+/)

[]{#backreference}[backreference in match and
substitution](#backreference-note)

/(\\w+) \\1/.exec(\'do do\')\
\
\'do re\'.replace(/(\\w+) (\\w+)/, \'\$2 \$1\')

[*none*]{style="color: gray"}\
\
rx = re.compile(\'(\\w+) (\\w+)\')\
rx.sub(r\'\\2 \\1\', \'do re\')

preg\_match(\'/(\\w+) \\1/\', \"do do\")\
\
\$s = \"do re\";\
\$rx = \'/(\\w+) (\\w+)/\';\
\$s = preg\_replace(\$rx, \'\\2 \\1\', \$s);

/(\\w+) \\1/.match(\"do do\")\
\
\"do re\".sub(/(\\w+) (\\w+)/, \'\\2 \\1\')

[]{#recursive-regex}[recursive regex](#recursive-regex-note)\
[ ]{style="white-space: pre-wrap;"}

[*none*]{style="color: gray"}

[*none*]{style="color: gray"}

\'/\\((\[\^()\]\*\|(\$R))\\)/\'

/(?\<foo\>\\((\[\^()\]\*\|\\g\<foo\>)\*\\))/

[]{#dates-time}[dates and time](#dates-time-note)

node.js

python

php

ruby

[]{#broken-down-datetime-type}[broken-down datetime
type](#broken-down-datetime-type-note)\
[ ]{style="white-space: pre-wrap;"}

Date

datetime.datetime

DateTime

Time

[]{#current-datetime}[current datetime](#current-datetime-note)

let t = new Date();

import datetime\
\
t = datetime.datetime.now()\
utc = datetime.datetime.utcnow()

\$t = new DateTime(\"now\");\
\$utc\_tmz = new DateTimeZone(\"UTC\");\
\$utc = new DateTime(\"now\", \$utc\_tmz);

t = Time.now\
utc = Time.now.utc

[]{#current-unix-epoch}[current unix epoch](#current-unix-epoch-note)

(new Date()).getTime() / 1000

import datetime\
\
t = datetime.datetime.now()\
epoch = int(t.strftime(\"%s\"))

\$epoch = time();

epoch = Time.now.to\_i

[]{#broken-down-datetime-to-unix-epoch}[broken-down datetime to unix
epoch](#broken-down-datetime-to-unix-epoch-note)

Math.round(t.getTime() / 1000)

from datetime import datetime as dt\
\
epoch = int(t.strftime(\"%s\"))

\$epoch = \$t-\>getTimestamp();

epoch = t.to\_i

[]{#unix-epoch-to-broken-down-datetime}[unix epoch to broken-down
datetime](#unix-epoch-to-broken-down-datetime-note)

let epoch = 1315716177;\
let t2 = new Date(epoch \* 1000);

t = dt.fromtimestamp(1304442000)

\$t2 = new DateTime();\
\$t2-\>setTimestamp(1304442000);

t = Time.at(1304442000)

[]{#fmt-datetime}[format datetime](#fmt-datetime-note)

[[//]{style="white-space: pre-wrap;"} npm install
moment]{style="color: gray"}\
let moment = require(\'moment\');\
\
let t = moment(new Date());\
let fmt = \'YYYY-MM-DD HH:mm:ss\';\
console.log(t.format(fmt));

t.strftime(\'%Y-%m-%d %H:%M:%S\')

strftime(\"%Y-%m-%d %H:%M:%S\", \$epoch);\
date(\"Y-m-d H:i:s\", \$epoch);\
\$t-\>format(\"Y-m-d H:i:s\");

t.strftime(\"%Y-%m-%d %H:%M:%S\")

[]{#parse-datetime}[parse datetime](#parse-datetime-note)

[[//]{style="white-space: pre-wrap;"} npm install
moment]{style="color: gray"}\
let moment = require(\'moment\');\
\
let fmt = \'YYYY-MM-DD HH:mm:ss\';\
let s = \'2011-05-03 10:00:00\';\
let t = moment(s, fmt);

from datetime import datetime\
\
s = \'2011-05-03 10:00:00\'\
fmt = \'%Y-%m-%d %H:%M:%S\'\
t = datetime.strptime(s, fmt)

\$fmt = \"Y-m-d H:i:s\";\
\$s = \"2011-05-03 10:00:00\";\
\$t = DateTime::createFromFormat(\$fmt,\
[  ]{style="white-space: pre-wrap;"}\$s);

require \'date\'\
\
s = \"2011-05-03 10:00:00\"\
fmt = \"%Y-%m-%d %H:%M:%S\"\
t = DateTime.strptime(s, fmt).to\_time

[]{#parse-datetime-without-fmt}[parse datetime w/o
format](#parse-datetime-without-fmt-note)

let t = new Date(\'July 7, 1999\');

[\# pip install python-dateutil]{style="color: gray"}\
import dateutil.parser\
\
s = \'July 7, 1999\'\
t = dateutil.parser.parse(s)

\$epoch = strtotime(\"July 7, 1999\");

require \'date\'\
\
s = \"July 7, 1999\"\
t = Date.parse(s).to\_time

[]{#date-parts}[date parts](#date-parts-note)

t.getFullYear()\
t.getMonth() + 1\
t.getDate() [[//]{style="white-space: pre-wrap;"} getDay() is day of
week]{style="color: gray"}

t.year\
t.month\
t.day

(int)\$t-\>format(\"Y\")\
(int)\$t-\>format(\"m\")\
(int)\$t-\>format(\"d\")

t.year\
t.month\
t.day

[]{#time-parts}[time parts](#time-parts-note)

t.getHours()\
t.getMinutes()\
t.getSeconds()

t.hour\
t.minute\
t.second

(int)\$t-\>format(\"H\")\
(int)\$t-\>format(\"i\")\
(int)\$t-\>format(\"s\")

t.hour\
t.min\
t.sec

[]{#build-datetime}[build broken-down datetime](#build-datetime-note)

let yr = 1999;\
let mo = 9;\
let dy = 10;\
let hr = 23;\
let mi = 30;\
let ss = 0;\
let t = new Date(yr, mo - 1, dy,\
[  ]{style="white-space: pre-wrap;"}hr, mi, ss);

import datetime\
\
yr = 1999\
mo = 9\
dy = 10\
hr = 23\
mi = 30\
ss = 0\
t = datetime.datetime(yr, mo, dy, hr, mi, ss)

yr = 1999\
mo = 9\
dy = 10\
hr = 23\
mi = 30\
ss = 0\
t = Time.new(yr, mo, dy, hr, mi, ss)

[]{#datetime-subtraction}[datetime
subtraction](#datetime-subtraction-note)

[number *containing time difference in
milliseconds*]{style="color: gray"}

[datetime.timedelta *object*]{style="color: gray"}\
\
[*use* total\_seconds() *method to convert to float representing
difference in seconds*]{style="color: gray"}

[\# DateInterval object if diff method used:]{style="color: gray"}\
\$fmt = \"Y-m-d H:i:s\";\
\$s = \"2011-05-03 10:00:00\";\
\$then = DateTime::createFromFormat(\$fmt, \$s);\
\$now = new DateTime(\"now\");\
\$interval = \$now-\>diff(\$then);

[Float *containing time difference in seconds*]{style="color: gray"}

[]{#add-duration}[add duration](#add-duration-note)

let t1 = new Date();\
let delta = (10 \* 60 + 3) \* 1000;\
let t2 = new Date(t1.getTime() + delta);

import datetime\
\
delta = datetime.timedelta(\
[  ]{style="white-space: pre-wrap;"}minutes=10,\
[  ]{style="white-space: pre-wrap;"}seconds=3)\
t = datetime.datetime.now() + delta

\$now = new DateTime(\"now\");\
\$now-\>add(new DateInterval(\"PT10M3S\");

require \'date/delta\'\
\
s = \"10 min, 3 s\"\
delta = Date::Delta.parse(s).in\_secs\
t = Time.now + delta

[]{#local-tmz-determination}[local time zone
determination](#local-tmz-determination-note)

[TZ environment variable or host time zone]{style="color: gray"}

[*a* datetime *object has no time zone information unless a* tzinfo
*object is provided when it is created*]{style="color: gray"}

[\# DateTime objects can be instantiated\
\# without specifying the time zone\
\# if a default is set:]{style="color: gray"}\
\$s = \"America/Los\_Angeles\";\
date\_default\_timezone\_set(\$s);

[*if no time zone is specified the local time zone is
used*]{style="color: gray"}

[]{#nonlocal-tmz}[nonlocal time zone](#nonlocal-tmz-note)

[\# pip install pytz]{style="color: gray"}\
import pytz\
import datetime\
\
tmz = pytz.timezone(\'Asia/Tokyo\')\
utc = datetime.datetime.utcnow()\
utc\_dt = datetime.datetime(\
[  ]{style="white-space: pre-wrap;"}\*utc.timetuple()\[0:6\],\
[  ]{style="white-space: pre-wrap;"}tzinfo=pytz.utc)\
jp\_dt = utc\_dt.astimezone(tmz)

[\# gem install tzinfo]{style="color: gray"}\
require \'tzinfo\'\
\
tmz = TZInfo::Timezone.get(\"Asia/Tokyo\")\
jp\_time = tmz.utc\_to\_local(Time.now.utc)

[]{#tmz-info}[time zone info](#tmz-info-note)\
\
[*name and UTC offset*]{style="color: gray"}

import time\
\
tm = time.localtime()\
[  ]{style="white-space: pre-wrap;"}\
time.tzname\[tm.tm\_isdst\]\
(time.timezone / -3600) + tm.tm\_isdst

\$tmz = date\_timezone\_get(\$t);\
\
timezone\_name\_get(\$tmz);\
date\_offset\_get(\$t) / 3600;

t.zone\
t.utc\_offset / 3600

[]{#daylight-savings-test}[daylight savings
test](#daylight-savings-test-note)

[[//]{style="white-space: pre-wrap;"} npm install
moment]{style="color: gray"}\
let moment = require(\'moment\');\
\
moment(new Date()).isDST()

import time\
\
tm = time.localtime()\
[  ]{style="white-space: pre-wrap;"}\
tm.tm\_isdst

\$t-\>format(\"I\");

t.dst?

[]{#microseconds}[microseconds](#microseconds-note)

t.getMilliseconds() \* 1000\
\
[[//]{style="white-space: pre-wrap;"} \[sec, nanosec\] since system
boot:]{style="color: gray"}\
process.hrtime()

t.microsecond

list(\$frac, \$sec) = explode(\" \", microtime());\
\$usec = \$frac \* 1000 \* 1000;

t.usec

[]{#arrays}[arrays](#arrays-note)

node.js

python

php

ruby

[]{#array-literal}[literal](#array-literal-note)\
[ ]{style="white-space: pre-wrap;"}

a = \[1, 2, 3, 4\]

a = \[1, 2, 3, 4\]

\$a = \[1, 2, 3, 4\];\
\
[\# older syntax:]{style="color: gray"}\
\$a = array(1, 2, 3, 4);

a = \[1, 2, 3, 4\]\
\
[\# a = \[\'do\', \'re\', \'mi\'\]]{style="color: gray"}\
a = %w(do re mi)

[]{#array-size}[size](#array-size-note)\
[ ]{style="white-space: pre-wrap;"}

a.length

len(a)

count(\$a)

a.size\
a.length

[]{#array-empty}[empty test](#array-empty-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} TypeError if a is null or
undefined:]{style="color: gray"}\
a.length === 0

[\# None tests as empty:]{style="color: gray"}\
not a

[\# NULL tests as empty:]{style="color: gray"}\
!\$a

[\# NoMethodError if a is nil:]{style="color: gray"}\
a.empty?

[]{#array-lookup}[lookup](#array-lookup-note)\
[ ]{style="white-space: pre-wrap;"}

a\[0\]

a\[0\]\
\
[\# returns last element:]{style="color: gray"}\
a\[-1\]

\$a\[0\]\
\
[\# PHP uses the same type for arrays and\
\# dictionaries; indices can be negative\
\# integers or strings]{style="color: gray"}

a\[0\]\
\
[\# returns last element:]{style="color: gray"}\
a\[-1\]

[]{#array-update}[update](#array-update-note)\
[ ]{style="white-space: pre-wrap;"}

a\[0\] = \'lorem\'

a\[0\] = \'lorem\'

\$a\[0\] = \"lorem\";

a\[0\] = \"lorem\"

[]{#array-out-of-bounds}[out-of-bounds
behavior](#array-out-of-bounds-note)

[*returns* undefined]{style="color: gray"}

a = \[\]\
[\# raises IndexError:]{style="color: gray"}\
a\[10\]\
[\# raises IndexError:]{style="color: gray"}\
a\[10\] = \'lorem\'

\$a = \[\];\
[\# evaluates as NULL:]{style="color: gray"}\
\$a\[10\];\
[\# increases array size to one:]{style="color: gray"}\
\$a\[10\] = \"lorem\";

a = \[\]\
[\# evaluates as nil:]{style="color: gray"}\
a\[10\]\
[\# increases array size to 11:]{style="color: gray"}\
a\[10\] = \"lorem\"

[]{#array-element-index}[element index](#array-element-index-note)\
\
[*first and last occurrence*]{style="color: gray"}

[[//]{style="white-space: pre-wrap;"} return -1 if not
found:]{style="color: gray"}\
\[6, 7, 7, 8\].indexOf(7)\
\[6, 7, 7, 8\].lastIndexOf(7)

a = \[\'x\', \'y\', \'y\', \'z\'\]\
\
[\# raises ValueError if not found:]{style="color: gray"}\
a.index(\'y\')\
[*none*]{style="color: gray"}

\$a = \[\"x\", \"y\", \"y\", \"z\"\];\
\
[\# returns FALSE if not found:]{style="color: gray"}\
\$i = array\_search(\"y\", \$a, TRUE);\
[*none*]{style="color: gray"}

a = %w(x y y z)\
\
[\# return nil if not found:]{style="color: gray"}\
a.index(\'y\')\
a.rindex(\'y\')

[]{#array-slice}[slice](#array-slice-note)\
[*by endpoints, by length*]{style="color: gray"}\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} select 3rd and 4th
elements:]{style="color: gray"}\
\[\'a\', \'b\', \'c\', \'d\'\].slice(2, 4)\
[*none*]{style="color: gray"}

[\# select 3rd and 4th elements:]{style="color: gray"}\
a\[2:4\]\
a\[[2:2]{style="white-space: pre-wrap;"} + 2\]

[\# select 3rd and 4th elements:]{style="color: gray"}\
[*none*]{style="color: gray"}\
array\_slice(\$a, 2, 2)

[\# select 3rd and 4th elements:]{style="color: gray"}\
a\[2..3\]\
a\[2, 2\]

[]{#array-slice-to-end}[slice to end](#array-slice-to-end-note)\
[ ]{style="white-space: pre-wrap;"}

\[\'a\', \'b\', \'c\', \'d\'\].slice(1)

a\[1:\]

array\_slice(\$a, 1)

a\[1..-1\]

[]{#array-back}[manipulate back](#array-back-note)\
[ ]{style="white-space: pre-wrap;"}

a = \[6, 7, 8\];\
a.push(9);\
i = a.pop();

a = \[6, 7, 8\]\
a.append(9)\
a.pop()

\$a = \[6, 7, 8\];\
array\_push(\$a, 9);\
\$a\[\] = 9; [\# same as array\_push]{style="color: gray"}\
array\_pop(\$a);

a = \[6, 7, 8\]\
a.push(9)\
a [\<\<]{style="white-space: pre-wrap;"} 9 [\# same as
push]{style="color: gray"}\
a.pop

[]{#array-front}[manipulate front](#array-front-note)\
[ ]{style="white-space: pre-wrap;"}

a = \[6, 7, 8\];\
a.unshift(5);\
i = a.shift();

a = \[6, 7, 8\]\
a.insert(0, 5)\
a.pop(0)

\$a = \[6, 7, 8\];\
array\_unshift(\$a, 5);\
array\_shift(\$a);

a = \[6, 7, 8\]\
a.unshift(5)\
a.shift

[]{#array-concatenation}[concatenate](#array-concatenation-note)

a = \[1, 2, 3\].concat(\[4, 5, 6\]);

a = \[1, 2, 3\]\
a2 = a + \[4, 5, 6\]\
a.extend(\[4, 5, 6\])

\$a = \[1, 2, 3\];\
\$a2 = array\_merge(\$a, \[4, 5, 6\]);\
\$a = array\_merge(\$a, \[4, 5, 6\]);

a = \[1, 2, 3\]\
a2 = a + \[4, 5, 6\]\
a.concat(\[4, 5, 6\])

[]{#replicate-array}[replicate](#replicate-array-note)

Array(10).fill(null)

a = \[None\] \* 10\
a = \[None for i in range(0, 10)\]

\$a = array\_fill(0, 10, NULL);

a = \[nil\] \* 10\
a = Array.new(10, nil)

[]{#array-copy}[copy](#array-copy-note)\
[*address copy, shallow copy, deep copy*]{style="color: gray"}

a = \[1, 2, \[3, 4\]\];\
a2 = a;\
a3 = a.slice(0);\
a4 = JSON.parse(JSON.stringify(a));

import copy\
\
a = \[1,2,\[3,4\]\]\
a2 = a\
a3 = list(a)\
a4 = copy.deepcopy(a)

\$a = \[1, 2, \[3, 4\]\];\
\$a2 =& \$a;\
[*none*]{style="color: gray"}\
\$a4 = \$a;

a = \[1,2,\[3,4\]\]\
a2 = a\
a3 = a.dup\
a4 = Marshal.load(Marshal.dump(a))

[]{#array-as-func-arg}[array as function
argument](#array-as-func-arg-note)

[*parameter contains address copy*]{style="color: gray"}

[*parameter contains address copy*]{style="color: gray"}

[*parameter contains deep copy*]{style="color: gray"}

[*parameter contains address copy*]{style="color: gray"}

[]{#iterate-over-array}[iterate over
elements](#iterate-over-array-note)\
[ ]{style="white-space: pre-wrap;"}

\[6, 7, 8\].forEach((n) =\> {\
[  ]{style="white-space: pre-wrap;"}console.log(n);\
});\
\
[[//]{style="white-space: pre-wrap;"} new in ES6:]{style="color: gray"}\
for (let n of \[6, 7, 8\]) {\
[  ]{style="white-space: pre-wrap;"}console.log(n);\
}

for i in \[1, 2, 3\]:\
[  ]{style="white-space: pre-wrap;"}print(i)

foreach (\[1, 2, 3\] as \$i) {\
[  ]{style="white-space: pre-wrap;"}echo \"\$i\\n\";\
}

\[1, 2, 3\].each { \|i\| puts i }

[]{#indexed-array-iteration}[iterate over indices and
elements](#indexed-array-iteration-note)

for (let i = 0; i \< a.length; ++i) {\
[  ]{style="white-space: pre-wrap;"}console.log(a\[i\]);\
}\
\
[[//]{style="white-space: pre-wrap;"} indices not guaranteed to be in
order:]{style="color: gray"}\
for (let i in a) {\
[  ]{style="white-space: pre-wrap;"}console.log(a\[i\]);\
}

a = \[\'do\', \'re\', \'mi\', \'fa\'\]\
for i, s in enumerate(a):\
[  ]{style="white-space: pre-wrap;"}print(\'%s at index %d\' % (s, i))

\$a = \[\"do\", \"re\", \"mi\" \"fa\"\];\
foreach (\$a as \$i =\> \$s) {\
[  ]{style="white-space: pre-wrap;"}echo \"\$s at index \$i\\n\";\
}

a = %w(do re mi fa)\
a.each\_with\_index do \|s, i\|\
[  ]{style="white-space: pre-wrap;"}puts \"\#{s} at index \#{i}\"\
end

[]{#range-iteration}[iterate over range](#range-iteration-note)

[*not space efficient; use C-style for loop*]{style="color: gray"}

[\# use range() in Python 3:]{style="color: gray"}\
for i in xrange(1, 1000001):\
[  ]{style="white-space: pre-wrap;"}[*code*]{style="color: gray"}

[*not space efficient; use C-style for loop*]{style="color: gray"}

(1..1\_000\_000).each do \|i\|\
[  ]{style="white-space: pre-wrap;"}[*code*]{style="color: gray"}\
end

[]{#range-array}[instantiate range as array](#range-array-note)

let a = \_.range(1, 11);

a = range(1, 11)\
[*Python 3:*]{style="color: gray"}\
a = list(range(1, 11))

\$a = range(1, 10);

a = (1..10).to\_a

[]{#array-reverse}[reverse](#array-reverse-note)\
[*non-destructive, in-place*]{style="color: gray"}

let a = \[1, 2, 3\];\
\
let a2 = a.slice(0).reverse();\
a.reverse();

a = \[1, 2, 3\]\
\
a\[::-1\]\
a.reverse()

\$a = \[1, 2, 3\];\
\
array\_reverse(\$a);\
\$a = array\_reverse(\$a);

a = \[1, 2, 3\]\
\
a.reverse\
a.reverse!

[]{#array-sort}[sort](#array-sort-note)\
[*non-destructive,\
in-place,\
custom comparision*]{style="color: gray"}

let a = \[3, 1, 4, 2\];\
\
let a2 = a.slice(0).sort();\
a.sort();

a = \[\'b\', \'A\', \'a\', \'B\'\]\
\
sorted(a)\
a.sort()\
[\# custom binary comparision\
\# removed from Python 3:]{style="color: gray"}\
a.sort(key=str.lower)

\$a = \[\"b\", \"A\", \"a\", \"B\"\];\
\
[*none*]{style="color: gray"}\
sort(\$a);\
[*none, but* usort *sorts in place*]{style="color: gray"}

a = %w(b A a B)\
\
a.sort\
a.sort!\
a.sort do \|x, y\|\
[  ]{style="white-space: pre-wrap;"}x.downcase \<=\> y.downcase\
end

[]{#array-dedupe}[dedupe](#array-dedupe-note)\
[*non-destructive, in-place*]{style="color: gray"}

let a = \[1, 2, 2, 3\];\
\
let a2 = \_.uniq(a);\
a = \_.uniq(a);

a = \[1, 2, 2, 3\]\
\
a2 = list(set(a))\
a = list(set(a))

\$a = \[1, 2, 2, 3\];\
\
\$a2 = array\_unique(\$a);\
\$a = array\_unique(\$a);

a = \[1, 2, 2, 3\]\
\
a2 = a.uniq\
a.uniq!

[]{#membership}[membership](#membership-note)\
[ ]{style="white-space: pre-wrap;"}

a.includes(7)

7 in a

in\_array(7, \$a)

a.include?(7)

[]{#intersection}[intersection](#intersection-note)\
[ ]{style="white-space: pre-wrap;"}

\_.intersection(\[1, 2\], \[2, 3, 4\])

{1, 2} & {2, 3, 4}

\$a = \[1, 2\];\
\$b = \[2, 3, 4\]\
array\_intersect(\$a, \$b)

\[1, 2\] & \[2 ,3, 4\]

[]{#union}[union](#union-note)\
[ ]{style="white-space: pre-wrap;"}

\_.union(\[1, 2\], \[2, 3, 4\])

{1, 2} \| {2, 3, 4}

\$a1 = \[1, 2\];\
\$a2 = \[2, 3, 4\];\
array\_unique(array\_merge(\$a1, \$a2))

\[1, 2\] \| \[2, 3, 4\]

[]{#set-diff}[relative complement, symmetric difference](#set-diff-note)

\_.difference(\[1, 2, 3\], \[2\])\
[*none*]{style="color: gray"}

{1, 2, 3} - {2}\
{1, 2} \^ {2, 3, 4}

\$a1 = \[1, 2, 3\];\
\$a2 = \[2\];\
array\_values(array\_diff(\$a1, \$a2))\
[*none*]{style="color: gray"}

require \'set\'\
\
\[1, 2, 3\] - \[2\]\
Set\[1, 2\] \^ Set\[2 ,3, 4\]

[]{#map}[map](#map-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} callback gets 3 args:\
[//]{style="white-space: pre-wrap;"} value, index,
array]{style="color: gray"}\
a.map((x) =\> x \* x)

map(lambda x: x \* x, \[1, 2, 3\])\
[\# or use list comprehension:]{style="color: gray"}\
\[x \* x for x in \[1, 2, 3\]\]

array\_map(function (\$x) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}return
\$x \* \$x;\
[  ]{style="white-space: pre-wrap;"}}, \[1, 2, 3\])

\[1, 2, 3\].map { \|o\| o \* o }

[]{#filter}[filter](#filter-note)\
[ ]{style="white-space: pre-wrap;"}

a.filter((x) =\> x \> 1)

filter(lambda x: x \> 1, \[1, 2, 3\])\
[\# or use list comprehension:]{style="color: gray"}\
\[x for x in \[1, 2, 3\] if x \> 1\]

array\_filter(\[1, 2, 3\],\
[  ]{style="white-space: pre-wrap;"}function (\$x) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}return
\$x\>1;\
[  ]{style="white-space: pre-wrap;"}})

\[1, 2, 3\].select { \|o\| o \> 1 }

[]{#reduce}[reduce](#reduce-note)\
[ ]{style="white-space: pre-wrap;"}

a.reduce((m, o) =\> m + o, 0)

[\# import needed in Python 3 only]{style="color: gray"}\
from functools import reduce\
\
reduce(lambda x, y: x + y, \[1, 2, 3\], 0)

array\_reduce(\[1, 2, 3\],\
[  ]{style="white-space: pre-wrap;"}function(\$x,\$y) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}return
\$x + \$y;\
[  ]{style="white-space: pre-wrap;"}}, 0)

\[1, 2, 3\].inject(0) { \|m, o\| m + o }

[]{#universal-existential-test}[universal and existential
tests](#universal-existential-test-note)\
[ ]{style="white-space: pre-wrap;"}

let a = \[1, 2, 3, 4\];\
\
a.every((n) =\> n % 2 === 0)\
a.some((n) =\> n % 2 === 0)

all(i % 2 == 0 for i in \[1, 2, 3, 4\])\
any(i % 2 == 0 for i in \[1, 2, 3, 4\])

[*use array\_filter*]{style="color: gray"}

\[1, 2, 3, 4\].all? {\|i\| i.even? }\
\[1, 2, 3, 4\].any? {\|i\| i.even? }

[]{#shuffle-sample}[shuffle and sample](#shuffle-sample-note)

let a = \[1, 2, 3, 4\];\
\
a = \_.shuffle(a);\
let samp = \_.sampleSize(\[1, 2, 3, 4\], 2);

from random import shuffle, sample\
\
a = \[1, 2, 3, 4\]\
shuffle(a)\
samp = sample(\[1, 2, 3, 4\], 2)

\$a = \[1, 2, 3, 4\];\
\
shuffle(\$a);\
\$samp = array\_rand(\|\[1, 2, 3, 4\], 2);

\[1, 2, 3, 4\].shuffle!\
samp = \[1, 2, 3, 4\].sample(2)

[]{#flatten}[flatten](#flatten-note)\
[*one level, completely*]{style="color: gray"}

let a = \[1, \[2, \[3, 4\]\]\];\
\
let a2 = \_.flatten(a);\
let a3 = \_.flattenDeep(a);

[*none*]{style="color: gray"}

[*none*]{style="color: gray"}

a = \[1, \[2, \[3, 4\]\]\]\
a2 = a.flatten(1)\
a3 = a.flatten

[]{#zip}[zip](#zip-note)\
[ ]{style="white-space: pre-wrap;"}

let a = \_.zip(\[1, 2, 3\], \[\'a\', \'b\', \'c\'\]);\
\
[[//]{style="white-space: pre-wrap;"} shorter array padded with
undefined:]{style="color: gray"}\
\_.zip(\[1, 2, 3\], \[\'a\', \'b\'\])

list(zip(\[1, 2, 3\], \[\'a\', \'b\', \'c\'\]))\
\
[\# extras in longer array dropped:]{style="color: gray"}\
list(zip(\[1, 2, 3\], \[\'a\', \'b\'\]))

\$a = array\_map(NULL,\
[  ]{style="white-space: pre-wrap;"}\[1, 2, 3\],\
[  ]{style="white-space: pre-wrap;"}\[\"a\", \"b\", \"c\"\]);\
\
[\# shorter array padded with NULLs]{style="color: gray"}

\[1, 2, 3\].zip(\[\"a\", \"b\", \"c\"\])\
\
[\# shorter array padded with nil:]{style="color: gray"}\
\[1, 2, 3\].zip(\[\"a\", \"b\"\])

[]{#dictionaries}[dictionaries](#dictionaries-note)

node.js

python

php

ruby

[]{#dict-literal}[literal](#dict-literal-note)\
[ ]{style="white-space: pre-wrap;"}

d = {t: 1, f: 0};\
[[//]{style="white-space: pre-wrap;"} keys do not need to be quoted if
they\
[//]{style="white-space: pre-wrap;"} are a legal JavaScript variable
name\
[//]{style="white-space: pre-wrap;"} and not a reserved
word]{style="color: gray"}

d = {\'t\': 1, \'f\': 0}

\$d = \[\"t\" =\> 1, \"f\" =\> 0\];\
\
[\# older syntax:]{style="color: gray"}\
\$d = array(\"t\" =\> 1, \"f\" =\> 0);

d = {\'t\' =\> 1, \'f\' =\> 0}\
\
[\# keys are symbols:]{style="color: gray"}\
symbol\_to\_int = {t: 1, f: 0}

[]{#dict-size}[size](#dict-size-note)\
[ ]{style="white-space: pre-wrap;"}

\_.size(d)\
Object.getOwnPropertyNames(d).length

len(d)

count(\$d)

d.size\
d.length

[]{#dict-lookup}[lookup](#dict-lookup-note)\
[ ]{style="white-space: pre-wrap;"}

d.hasOwnProperty(\"t\") ? d\[\"t\"\] : undefined\
d.hasOwnProperty(\"t\") ? d.t : undefined\
\
[[//]{style="white-space: pre-wrap;"} JavaScript dictionaries are
objects\
[//]{style="white-space: pre-wrap;"} and inherit properties from
Object.]{style="color: gray"}

d\[\'t\'\]

\$d\[\"t\"\]

d\[\'t\'\]

[]{#dict-update}[update](#dict-update-note)

d\[\'t\'\] = 2;\
d.t = 2;

d\[\'t\'\] = 2\
\
[\# provide default to avoid KeyError:]{style="color: gray"}\
d.get(\'t\', None)

\$d\[\"t\"\] = 2;

d\[\'t\'\] = 2

[]{#dict-missing-key}[missing key behavior](#dict-missing-key-note)\
[ ]{style="white-space: pre-wrap;"}

let d = {};\
[[//]{style="white-space: pre-wrap;"} undefined:]{style="color: gray"}\
d\[\"lorem\"\];\
[[//]{style="white-space: pre-wrap;"} adds key/value
pair:]{style="color: gray"}\
d\[\"lorem\"\] = \"ipsum\";

d = {}\
[\# raises KeyError:]{style="color: gray"}\
d\[\'lorem\'\]\
[\# adds key/value pair:]{style="color: gray"}\
d\[\'lorem\'\] = \'ipsum\'

\$d = \[\];\
[\# NULL:]{style="color: gray"}\
\$d\[\"lorem\"\];\
[\# adds key/value pair:]{style="color: gray"}\
\$d\[\"lorem\"\] = \"ipsum\";

d = {}\
[\# nil:]{style="color: gray"}\
d\[\'lorem\'\]\
[\# adds key/value pair:]{style="color: gray"}\
d\[\'lorem\'\] = \'ipsum\'

[]{#dict-key-check}[is key present](#dict-key-check-note)\
[ ]{style="white-space: pre-wrap;"}

d.hasOwnProperty(\"t\");

\'y\' in d

array\_key\_exists(\"y\", \$d);

d.key?(\'y\')

[]{#dict-delete}[delete](#dict-delete-note)

delete d\[\"t\"\];\
delete d.t;

d = {1: True, 0: False}\
del d\[1\]

\$d = \[1 =\> \"t\", 0 =\> \"f\"\];\
unset(\$d\[1\]);

d = {1 =\> true, 0 =\> false}\
d.delete(1)

[]{#dict-assoc-array}[from array of pairs, from even length
array](#dict-assoc-array-note)

let a = \[\[\'a\', 1\], \[\'b\', 2\], \[\'c\', 3\]\];\
let d = \_.fromPairs(a);\
\
[*none*]{style="color: gray"}

a = \[\[\'a\', 1\], \[\'b\', 2\], \[\'c\', 3\]\]\
d = dict(a)\
\
a = \[\'a\', 1, \'b\', 2, \'c\', 3\]\
d = dict(zip(a\[::2\], a\[1::2\]))

a = \[\[\'a\', 1\], \[\'b\', 2\], \[\'c\', 3\]\]\
d = Hash\[a\]\
\
a = \[\'a\', 1, \'b\', 2, \'c\', 3\]\
d = Hash\[\*a\]

[]{#dict-merge}[merge](#dict-merge-note)

let d1 = {a: 1, b: 2};\
let d2 = {b: 3, c: 4};\
[[//]{style="white-space: pre-wrap;"} d2 overwrites shared keys in
d1:]{style="color: gray"}\
d1 = \_.assignIn(d1, d2);

d1 = {\'a\': 1, \'b\': 2}\
d2 = {\'b\': 3, \'c\': 4}\
d1.update(d2)

\$d1 = \[\"a\" =\> 1, \"b\" =\> 2\];\
\$d2 = \[\"b\" =\> 3, \"c\" =\> 4\];\
\$d1 = array\_merge(\$d1, \$d2);

d1 = {\'a\' =\> 1, \'b\' =\> 2}\
d2 = {\'b\' =\> 3, \'c\' =\> 4}\
d1.merge!(d2)

[]{#dict-invert}[invert](#dict-invert-note)

let let2num = {t: 1, f: 0};\
let num2let = \_.invert(let2num);

to\_num = {\'t\': 1, \'f\': 0}\
[\# dict comprehensions added in 2.7:]{style="color: gray"}\
to\_let = {v: k for k, v\
[  ]{style="white-space: pre-wrap;"}in to\_num.items()}

\$to\_num = \[\"t\" =\> 1, \"f\" =\> 0\];\
\$to\_let = array\_flip(\$to\_num);

to\_num = {\'t\' =\> 1, \'f\' =\> 0}\
to\_let = to\_num.invert

[]{#dict-iter}[iterate](#dict-iter-note)\
[ ]{style="white-space: pre-wrap;"}

for (let k in d) {\
[  ]{style="white-space: pre-wrap;"}console.log([\`]{style="white-space: pre-wrap;"}value
at \${k} is \${d\[k\]}[\`]{style="white-space: pre-wrap;"});\
}

for k, v in d.items():\
[  ]{style="white-space: pre-wrap;"}print(\'value at {} is
{}\'.format(k, v)\
\
[\# Python 2: use iteritems()]{style="color: gray"}

foreach (\$d as \$k =\> \$v) {\
[  ]{style="white-space: pre-wrap;"}echo \"value at \${k} is \${v}\";\
}

d.each do \|k,v\|\
[  ]{style="white-space: pre-wrap;"}puts \"value at \#{k} is \#{v}\"\
end

[]{#dict-key-val}[keys and values as arrays](#dict-key-val-note)

Object.keys(d)\
\_.values(d)

list(d.keys())\
list(d.values())\
\
[\# keys() and values return iterators\
\# in Python 3 and lists in Python 2]{style="color: gray"}

array\_keys(\$d)\
array\_values(\$d)

d.keys\
d.values

[]{#dict-sort-values}[sort by values](#dict-sort-values-note)

let cmp = (a, b) =\> a\[1\] - b\[1\];\
let d = {t: 1, f: 0};\
\
for (let p of \_.toPairs(d).sort(cmp)) {\
[  ]{style="white-space: pre-wrap;"}console.log(p);\
}

from operator import itemgetter\
\
pairs = sorted(d.items(), key=itemgetter(1))\
\
for k, v in pairs:\
[  ]{style="white-space: pre-wrap;"}print(\'{}: {}\'.format(k, v))

asort(\$d);\
\
foreach (\$d as \$k =\> \$v) {\
[  ]{style="white-space: pre-wrap;"}print \"\$k: \$v\\n\";\
}

d.sort\_by { \|k, v\| v }.each do \|k, v\|\
[  ]{style="white-space: pre-wrap;"}puts \"\#{k}: \#{v}\"\
end

[]{#dict-default-val}[default value, computed
value](#dict-default-val-note)

[*none*]{style="color: gray"}

from collections import defaultdict\
\
counts = defaultdict(lambda: 0)\
counts\[\'foo\'\] += 1\
\
class Factorial(dict):\
[  ]{style="white-space: pre-wrap;"}def
[\_\_missing\_\_]{style="white-space: pre-wrap;"}(self, k):\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}if
k \> 1:\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}return
k \* self\[k-1\]\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}else:\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}return
1\
\
factorial = Factorial()

\$counts = \[\];\
\$counts\[\'foo\'\] += 1;\
\
[\# For computed values and defaults other than\
\# zero or empty string, extend ArrayObject.]{style="color: gray"}

counts = Hash.new(0)\
counts\[\'foo\'\] += 1\
\
factorial = Hash.new do \|h,k\|\
[  ]{style="white-space: pre-wrap;"}k \> 1 ? k \* h\[k-1\] : 1\
end

[]{#functions}[functions](#functions-note)

node.js

python

php

ruby

[]{#def-func}[define](#def-func-note)\
[ ]{style="white-space: pre-wrap;"}

function add3 (x1, x2, x3) {\
[  ]{style="white-space: pre-wrap;"}return x1 + x2 + x3;\
}

def add3(x1, x2, x3):\
[  ]{style="white-space: pre-wrap;"}return x1 + x2 + x3

function add3(\$x1, \$x2, \$x3)\
{\
[  ]{style="white-space: pre-wrap;"}return \$x1 + \$x2 + \$x3;\
}

def add3(x1, x2, x3)\
[  ]{style="white-space: pre-wrap;"}x1 + x2 + x3\
end\
\
[\# parens are optional and customarily\
\# omitted when defining functions\
\# with no parameters]{style="color: gray"}

[]{#invoke-func}[invoke](#invoke-func-note)

add3(1, 2, 3)

add3(1, 2, 3)

add3(1, 2, 3);\
\
[\# function names are case insensitive:]{style="color: gray"}\
ADD3(1, 2, 3);

add3(1, 2, 3)\
\
[\# parens are optional:]{style="color: gray"}\
add3 1, 2, 3

[]{#missing-arg}[missing argument behavior](#missing-arg-note)\
[ ]{style="white-space: pre-wrap;"}

[*set to* undefined]{style="color: gray"}

[*raises* TypeError *if number of arguments doesn\'t match function
arity*]{style="color: gray"}

[*set to* NULL *with warning*]{style="color: gray"}

[*raises* ArgumentError *if number of arguments doesn\'t match function
arity*]{style="color: gray"}

[]{#extra-arg}[extra argument behavior](#extra-arg-note)\
[ ]{style="white-space: pre-wrap;"}

[*ignored*]{style="color: gray"}

[*raises* TypeError *if number of arguments doesn\'t match function
arity*]{style="color: gray"}

[*ignored*]{style="color: gray"}

[*raises* ArgumentError *if number of arguments doesn\'t match function
arity*]{style="color: gray"}

[]{#default-arg}[default argument](#default-arg-note)\
[ ]{style="white-space: pre-wrap;"}

[[//]{style="white-space: pre-wrap;"} new in ES6:]{style="color: gray"}\
function myLog (x, base = 10) {\
[  ]{style="white-space: pre-wrap;"}return Math.log(x) /
Math.log(base);\
}

import math\
\
def my\_log(x, base=10):\
[  ]{style="white-space: pre-wrap;"}return math.log(x) / math.log(base)\
\
my\_log(42)\
my\_log(42, math.e)

function my\_log(\$x, \$base=10)\
{\
[  ]{style="white-space: pre-wrap;"}return log(\$x) / log(\$base);\
}\
\
my\_log(42);\
my\_log(42, M\_E);

def my\_log(x, base=10)\
[  ]{style="white-space: pre-wrap;"}Math.log(x) / Math.log(base)\
end\
\
my\_log(42)\
my\_log(42, Math::E)

[]{#variadic-func}[variadic function](#variadic-func-note)

function firstAndLast() {\
[  ]{style="white-space: pre-wrap;"}if (arguments.length \>= 1) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}console.log(\'first:
\' + arguments\[0\]);\
[  ]{style="white-space: pre-wrap;"}}\
[  ]{style="white-space: pre-wrap;"}if (arguments.length \>= 2) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}console.log(\'last:
\' + arguments\[1\]);\
[  ]{style="white-space: pre-wrap;"}}\
}\
\
[[// \...]{style="white-space: pre-wrap;"} operator new in
ES6:]{style="color: gray"}\
function firstAndLast([\...]{style="white-space: pre-wrap;"}a) {\
[  ]{style="white-space: pre-wrap;"}if (a.length \>= 1) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}console.log(\'first:
\' + a\[0\]);\
[  ]{style="white-space: pre-wrap;"}}\
[  ]{style="white-space: pre-wrap;"}if (a.length \>= 2) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}console.log(\'last:
\' + a\[1\]);\
[  ]{style="white-space: pre-wrap;"}}\
}

def first\_and\_last(\*a):\
\
[  ]{style="white-space: pre-wrap;"}if len(a) \>= 1:\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}print(\'first:
\' + str(a\[0\]))\
\
[  ]{style="white-space: pre-wrap;"}if len(a) \>= 2:\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}print(\'last:
\' + str(a\[-1\]))

function first\_and\_last()\
{\
\
[  ]{style="white-space: pre-wrap;"}\$arg\_cnt = func\_num\_args();\
\
[  ]{style="white-space: pre-wrap;"}if (\$arg\_cnt \>= 1) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}\$n
= func\_get\_arg(0);\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}echo
\"first: \" . \$n . \"\\n\";\
[  ]{style="white-space: pre-wrap;"}}\
\
[  ]{style="white-space: pre-wrap;"}if (\$arg\_cnt \>= 2) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}\$a
= func\_get\_args();\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}\$n
= \$a\[\$arg\_cnt-1\];\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}echo
\"last: \" . \$n . \"\\n\";\
[  ]{style="white-space: pre-wrap;"}}\
}

def first\_and\_last(\*a)\
\
[  ]{style="white-space: pre-wrap;"}if a.size \>= 1\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}puts
\"first: \#{a\[0\]}\"\
[  ]{style="white-space: pre-wrap;"}end\
\
[  ]{style="white-space: pre-wrap;"}if a.size \>= 2\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}puts
\"last: \#{a\[-1\]}\"\
[  ]{style="white-space: pre-wrap;"}end\
end

[]{#apply-func}[pass array elements as separate
arguments](#apply-func-note)

let a = \[1, 2, 3\];\
\
let sum = add3([\...]{style="white-space: pre-wrap;"}a);

a = \[2, 3\]\
\
add3(1, \*a)\
\
[\# splat operator can only be used once\
\# and must appear after other\
\# unnamed arguments]{style="color: gray"}

\$a = \[1, 2, 3\];\
\
call\_user\_func\_array(\"add3\", \$a);

a = \[2, 3\]\
\
add3(1, \*a)\
\
[\# splat operator can be used multiple\
\# times and can appear before regular\
\# arguments]{style="color: gray"}

[]{#param-alias}[parameter alias](#param-alias-note)

[*none*]{style="color: gray"}

[*none*]{style="color: gray"}

function first\_and\_second(&\$a)\
{\
[  ]{style="white-space: pre-wrap;"}return \[\$a\[0\], \$a\[1\]\];\
}

[*none*]{style="color: gray"}

[]{#named-param}[named parameters](#named-param-note)\
[ ]{style="white-space: pre-wrap;"}

[*none*]{style="color: gray"}

def fequal(x, y, eps=0.01):\
[  ]{style="white-space: pre-wrap;"}return abs(x - y) \< eps\
\
fequal(1.0, 1.001)\
fequal(1.0, 1.001, eps=0.1[\*\*]{style="white-space: pre-wrap;"}10)

[*none*]{style="color: gray"}

def fequals(x, y, eps: 0.01)\
[  ]{style="white-space: pre-wrap;"}(x - y).abs \< eps\
end\
\
fequals(1.0, 1.001)\
fequals(1.0, 1.001, eps: 0.1\*\*10)

[]{#retval}[return value](#retval-note)\
[ ]{style="white-space: pre-wrap;"}

[return *arg or* undefined.]{style="color: gray"}\
\
[*If invoked with* new *and* return *value not an object, returns*
this.]{style="color: gray"}

[return *arg or* None]{style="color: gray"}

[return *arg or* NULL]{style="color: gray"}

[return *arg or last expression evaluated*]{style="color: gray"}

[]{#multiple-retval}[multiple return values](#multiple-retval-note)\
[ ]{style="white-space: pre-wrap;"}

function firstAndSecond(a) {\
[  ]{style="white-space: pre-wrap;"}return \[a\[0\], a\[1\]\];\
}\
\
let \[x, y\] = firstAndSecond(\[6, 7, 8\]);\

def first\_and\_second(a):\
[  ]{style="white-space: pre-wrap;"}return a\[0\], a\[1\]\
\
x, y = first\_and\_second(\[6, 7, 8\])

function first\_and\_second(&\$a)\
{\
[  ]{style="white-space: pre-wrap;"}return \[\$a\[0\], \$a\[1\]\];\
}\
\
\$a = \[6, 7, 8\];\
list(\$x, \$y) =\
[  ]{style="white-space: pre-wrap;"}first\_and\_second(\$a);

def first\_and\_second(a)\
[  ]{style="white-space: pre-wrap;"}return a\[0\], a\[1\]\
end\
\
x, y = first\_and\_second(\[6, 7, 8\])

[]{#anonymous-func-literal}[anonymous function
literal](#anonymous-func-literal-note)\
[ ]{style="white-space: pre-wrap;"}

let square = function (x) {\
[  ]{style="white-space: pre-wrap;"}return x \* x;\
};\
\
[[//]{style="white-space: pre-wrap;"} =\> new in
ES6:]{style="color: gray"}\
let square = (x) =\> { return x \* x; };\
\
[[//]{style="white-space: pre-wrap;"} expression body
variant:]{style="color: gray"}\
let square = (x) =\> x \* x;

[\# body must be an expression:]{style="color: gray"}\
square = lambda x: x \* x

\$square = function (\$x) {\
[  ]{style="white-space: pre-wrap;"}return \$x \* \$x;\
};

square = lambda { \|x\| x \* x }

[]{#invoke-anonymous-func}[invoke anonymous
function](#invoke-anonymous-func-note)

square(2)\
\
((x) =\> (x \* x)(2)

square(2)\
\
(lambda x: x \* x)(2)

\$square(2)

square.call(2)\
\
[\# alternative syntax:]{style="color: gray"}\
square\[2\]

[]{#func-as-val}[function as value](#func-as-val-note)\
[ ]{style="white-space: pre-wrap;"}

let func = add3;

func = add3

\$func = \"add3\";

func = lambda { \|\*args\| add3(\*args) }

[]{#private-state-func}[function with private
state](#private-state-func-note)

function counter() {\
[  ]{style="white-space: pre-wrap;"}counter.i += 1;\
[  ]{style="white-space: pre-wrap;"}return counter.i;\
}\
\
counter.i = 0;\
console.log(counter());

[\# state not private:]{style="color: gray"}\
def counter():\
[  ]{style="white-space: pre-wrap;"}counter.i += 1\
[  ]{style="white-space: pre-wrap;"}return counter.i\
\
counter.i = 0\
print(counter())

function counter()\
{\
[  ]{style="white-space: pre-wrap;"}static \$i = 0;\
[  ]{style="white-space: pre-wrap;"}return ++\$i;\
}\
\
echo counter();

[*none*]{style="color: gray"}

[]{#closure}[closure](#closure-note)

function makeCounter () {\
[  ]{style="white-space: pre-wrap;"}let i = 0;\
\
[  ]{style="white-space: pre-wrap;"}return function () {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}i
+= 1;\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}return
i;\
[  ]{style="white-space: pre-wrap;"}};\
}\
\
let nays = makeCounter();\
console.log(nays());

def make\_counter():\
[  ]{style="white-space: pre-wrap;"}i = 0\
[  ]{style="white-space: pre-wrap;"}def counter():\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[\#
new in Python 3:]{style="color: gray"}\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}nonlocal
i\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}i
+= 1\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}return
i\
[  ]{style="white-space: pre-wrap;"}return counter\
\
nays = make\_counter()\
print(nays())

function make\_counter()\
{\
[  ]{style="white-space: pre-wrap;"}\$i = 0;\
[  ]{style="white-space: pre-wrap;"}return function () use (&\$i) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}return
++\$i;\
[  ]{style="white-space: pre-wrap;"}};\
}\
\
\$nays = make\_counter();\
echo \$nays();

def make\_counter\
[  ]{style="white-space: pre-wrap;"}i = 0\
[  ]{style="white-space: pre-wrap;"}return lambda { i +=1; i }\
end\
\
nays = make\_counter\
puts nays.call

[]{#generator}[generator](#generator-note)

function \* makeCounter () {\
[  ]{style="white-space: pre-wrap;"}let i = 0;\
[  ]{style="white-space: pre-wrap;"}while (true) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}yield
++i;\
[  ]{style="white-space: pre-wrap;"}}\
}\
\
let nays = makeCounter();\
for (let cnt of nays) {\
[  ]{style="white-space: pre-wrap;"}console.log(cnt);\
[  ]{style="white-space: pre-wrap;"}if (cnt \> 100) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}break;\
[  ]{style="white-space: pre-wrap;"}}\
}

[\# cf. itertools library]{style="color: gray"}\
\
def make\_counter():\
[  ]{style="white-space: pre-wrap;"}i = 0\
[  ]{style="white-space: pre-wrap;"}while True:\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}i
+= 1\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}yield
i\
\
nays = make\_counter()\
[\# Python 2: nays.next()]{style="color: gray"}\
print(next(nays))\
\
for cnt in nays:\
[  ]{style="white-space: pre-wrap;"}print(cnt)\
[  ]{style="white-space: pre-wrap;"}if cnt \> 100:\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}break\
\
[\# Returning without yielding raises\
\# StopIteration exception.]{style="color: gray"}

[\# PHP 5.5:]{style="color: gray"}\
function make\_counter() {\
[  ]{style="white-space: pre-wrap;"}\$i = 0;\
[  ]{style="white-space: pre-wrap;"}while (1) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}yield
++\$i;\
[  ]{style="white-space: pre-wrap;"}}\
}\
\
\$nays = make\_counter();\
[\# does not return a value:]{style="color: gray"}\
\$nays-\>next();\
[\# runs generator if generator has not\
\# yet yielded:]{style="color: gray"}\
echo \$nays-\>current();

def make\_counter\
[  ]{style="white-space: pre-wrap;"}return Fiber.new do\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}i
= 0\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}while
true\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}i
+= 1\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}Fiber.yield
i\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}end\
[  ]{style="white-space: pre-wrap;"}end\
end\
\
nays = make\_counter\
puts nays.resume

[]{#decorator}[decorator](#decorator-note)

[*none*]{style="color: gray"}

def logcall(f):\
[  ]{style="white-space: pre-wrap;"}def wrapper(\*a, \*\*opts):\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}print(\'calling
\' + f.[\_\_name\_\_]{style="white-space: pre-wrap;"})\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}f(\*a,
\*\*opts)\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}print(\'called
\' + f.[\_\_name\_\_]{style="white-space: pre-wrap;"})\
[  ]{style="white-space: pre-wrap;"}return wrapper\
\
\@logcall\
def square(x):\
[  ]{style="white-space: pre-wrap;"}return x \* x

[]{#invoke-op-like-func}[invoke operator like
function](#invoke-op-like-func-note)

[*none*]{style="color: gray"}

import operator\
\
operator.mul(3, 7)\
\
a = \[\'foo\', \'bar\', \'baz\'\]\
operator.itemgetter(2)(a)

3.\*(7)\
\
a = \[\'foo\', \'bar\', \'baz\'\]\
a.\[\](2)

[]{#execution-control}[execution control](#execution-control-note)

node.js

python

php

ruby

[]{#if}[if](#if-note)\
[ ]{style="white-space: pre-wrap;"}

if (n === 0) {\
[  ]{style="white-space: pre-wrap;"}console.log(\'no hits\');\
} else if (n === 1) {\
[  ]{style="white-space: pre-wrap;"}console.log(\'1 hit\');\
} else {\
[  ]{style="white-space: pre-wrap;"}console.log(n + \' hits\');\
}

if 0 == n:\
[  ]{style="white-space: pre-wrap;"}print(\'no hits\')\
elif 1 == n:\
[  ]{style="white-space: pre-wrap;"}print(\'one hit\')\
else:\
[  ]{style="white-space: pre-wrap;"}print(str(n) + \' hits\')

if ( 0 == \$n ) {\
[  ]{style="white-space: pre-wrap;"}echo \"no hits\\n\";\
} elseif ( 1 == \$n ) {\
[  ]{style="white-space: pre-wrap;"}echo \"one hit\\n\";\
} else {\
[  ]{style="white-space: pre-wrap;"}echo \"\$n hits\\n\";\
}

if n == 0\
[  ]{style="white-space: pre-wrap;"}puts \"no hits\"\
elsif 1 == n\
[  ]{style="white-space: pre-wrap;"}puts \"one hit\"\
else\
[  ]{style="white-space: pre-wrap;"}puts \"\#{n} hits\"\
end

[]{#switch}[switch](#switch-note)

switch (n) {\
case 0:\
[  ]{style="white-space: pre-wrap;"}console.log(\'no hits\\n;);\
[  ]{style="white-space: pre-wrap;"}break;\
case 1:\
[  ]{style="white-space: pre-wrap;"}console.log(\'one hit\\n\');\
[  ]{style="white-space: pre-wrap;"}break;\
default:\
[  ]{style="white-space: pre-wrap;"}console.log(n + \' hits\\n\');\
}

[*none*]{style="color: gray"}

switch (\$n) {\
case 0:\
[  ]{style="white-space: pre-wrap;"}echo \"no hits\\n\";\
[  ]{style="white-space: pre-wrap;"}break;\
case 1:\
[  ]{style="white-space: pre-wrap;"}echo \"one hit\\n\";\
[  ]{style="white-space: pre-wrap;"}break;\
default:\
[  ]{style="white-space: pre-wrap;"}echo \"\$n hits\\n\";\
}

case n\
when 0\
[  ]{style="white-space: pre-wrap;"}puts \"no hits\"\
when 1\
[  ]{style="white-space: pre-wrap;"}puts \"one hit\"\
else\
[  ]{style="white-space: pre-wrap;"}puts \"\#{n} hits\"\
end

[]{#while}[while](#while-note)\
[ ]{style="white-space: pre-wrap;"}

while (i \< 100) {\
[  ]{style="white-space: pre-wrap;"}i += 1;\
}

while i \< 100:\
[  ]{style="white-space: pre-wrap;"}i += 1

while ( \$i \< 100 ) { \$i++; }

while i \< 100 do\
[  ]{style="white-space: pre-wrap;"}i += 1\
end

[]{#for}[for](#for-note)\
[ ]{style="white-space: pre-wrap;"}

for (let i = 0; i \< 10; ++i) {\
[  ]{style="white-space: pre-wrap;"}console.log(i);\
}

for i in range(1, 11):\
[  ]{style="white-space: pre-wrap;"}print(i)

for (\$i = 1; \$i \<= 10; \$i++) {\
[  ]{style="white-space: pre-wrap;"}echo \"\$i\\n\";\
}

[*none*]{style="color: gray"}

[]{#break}[break](#break-note)\
[ ]{style="white-space: pre-wrap;"}

for (let i = 30; i \< 50; ++i) {\
[  ]{style="white-space: pre-wrap;"}if (i % 7 === 0) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}console.log(\'first
multiple: \' + i);\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}break;\
[  ]{style="white-space: pre-wrap;"}}\
}

break

break

break

[]{#continue}[continue](#continue-note)\
[ ]{style="white-space: pre-wrap;"}

for (let i = 30; i \< 50; ++i) {\
[  ]{style="white-space: pre-wrap;"}if (i % 7 === 0) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}continue;\
[  ]{style="white-space: pre-wrap;"}}\
[  ]{style="white-space: pre-wrap;"}console.log(\'not divisible: \' +
i);\
}

continue

continue

next

[]{#statement-modifiers}[statement
modifiers](#statement-modifiers-note)\
[ ]{style="white-space: pre-wrap;"}

[*none*]{style="color: gray"}

[*none*]{style="color: gray"}

[*none*]{style="color: gray"}

puts \"positive\" if i \> 0\
puts \"nonzero\" unless i == 0

[]{#exceptions}[exceptions](#exceptions-note)

node.js

python

php

ruby

[]{#base-exc}[base exception](#base-exc-note)

[*Any value can be thrown.*]{style="color: gray"}

BaseException\
\
[*User-defined exceptions should subclass*
Exception.]{style="color: gray"}\
\
[*In Python 2 old-style classes can be thrown.*]{style="color: gray"}

Exception

Exception\
\
[*User-defined exceptions should subclass*
StandardError.]{style="color: gray"}

[]{#predefined-exc}[predefined exceptions](#predefined-exc-note)

Error\
[  ]{style="white-space: pre-wrap;"}EvalError\
[  ]{style="white-space: pre-wrap;"}RangeError\
[  ]{style="white-space: pre-wrap;"}ReferenceError\
[  ]{style="white-space: pre-wrap;"}SyntaxError\
[  ]{style="white-space: pre-wrap;"}TypeError\
[  ]{style="white-space: pre-wrap;"}URIError

BaseException\
[  ]{style="white-space: pre-wrap;"}Exception\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}TypeError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}ImportError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}AssertionError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}ArithmeticError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}FloatingPointError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}OverflowError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}ZeroDivisionError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}SyntaxError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}OSError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}MemoryError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}StopIteration\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}Error\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}SystemError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}ValueError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}UnicodeError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}UnicodeEncodeError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}UnicodeDecodeError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}UnicodeTranslateError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}UnsupportedOperation\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}NameError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}AttributeError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}RuntimeError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}LookupError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}IndexError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}KeyError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}EOFError\
[  ]{style="white-space: pre-wrap;"}GeneratorExit\
[  ]{style="white-space: pre-wrap;"}KeyboardInterrupt\
[  ]{style="white-space: pre-wrap;"}SystemExit

Exception\
[  ]{style="white-space: pre-wrap;"}LogicException\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}BadFunctionCallException\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}BadMethodCallException\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}DomainException\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}InvalidArgumentException\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}LengthException\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}OutOfRangeException\
[  ]{style="white-space: pre-wrap;"}RuntimeException\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}OutOfBoundsException\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}OverflowException\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}RangeException\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}UnderflowException\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}UnexpectedValueException

Exception\
[  ]{style="white-space: pre-wrap;"}NoMemoryError\
[  ]{style="white-space: pre-wrap;"}ScriptError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}LoadError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}NotImplementedError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}SyntaxError\
[  ]{style="white-space: pre-wrap;"}SignalException\
[  ]{style="white-space: pre-wrap;"}StandardError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}ArgumentError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}IOError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}EOFError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}IndexError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}LocalJumpError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}NameError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}RangeError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}RegexpError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}RuntimeError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}SecurityError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}SocketError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}SystemCallError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}Errno::\*\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}SystemStackError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}ThreadError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}TypeError\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}ZeroDivisionError\
[  ]{style="white-space: pre-wrap;"}SystemExit\
[  ]{style="white-space: pre-wrap;"}fatal

[]{#raise-exc}[raise exception](#raise-exc-note)\
[ ]{style="white-space: pre-wrap;"}

throw new Error(\"bad arg\");

raise Exception(\'bad arg\')

throw new Exception(\"bad arg\");

[\# raises RuntimeError]{style="color: gray"}\
raise \"bad arg\"

[]{#catch-all-handler}[catch-all handler](#catch-all-handler-note)\
[ ]{style="white-space: pre-wrap;"}

try {\
[  ]{style="white-space: pre-wrap;"}risky();\
} catch (e) {\
[  ]{style="white-space: pre-wrap;"}console.log(\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}\'risky
failed: \' + e.message);\
}

try:\
[  ]{style="white-space: pre-wrap;"}risky()\
except:\
[  ]{style="white-space: pre-wrap;"}print(\'risky failed\')

try {\
[  ]{style="white-space: pre-wrap;"}risky();\
} catch (Exception \$e) {\
[  ]{style="white-space: pre-wrap;"}echo \"risky failed: \",\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}\$e-\>getMessage(),
\"\\n\";\
}

[\# catches StandardError]{style="color: gray"}\
begin\
[  ]{style="white-space: pre-wrap;"}risky\
rescue\
[  ]{style="white-space: pre-wrap;"}print \"risky failed: \"\
[  ]{style="white-space: pre-wrap;"}puts \$!.message\
end

[]{#re-raise-exc}[re-raise exception](#re-raise-exc-note)

try {\
[  ]{style="white-space: pre-wrap;"}throw new Error(\"bam!\");\
} catch (e) {\
[  ]{style="white-space: pre-wrap;"}console.log(\'re-raising[\...]{style="white-space: pre-wrap;"}\');\
[  ]{style="white-space: pre-wrap;"}throw e;\
}

try:\
[  ]{style="white-space: pre-wrap;"}raise Exception(\'bam!\')\
except:\
[  ]{style="white-space: pre-wrap;"}print(\'re-raising[\...]{style="white-space: pre-wrap;"}\')\
[  ]{style="white-space: pre-wrap;"}raise

begin\
[  ]{style="white-space: pre-wrap;"}raise \"bam!\"\
rescue\
[  ]{style="white-space: pre-wrap;"}puts \"re-raising...\"\
[  ]{style="white-space: pre-wrap;"}raise\
end\
\
[\# if rescue clause raises different exception,\
\# original exception preserved at e.cause]{style="color: gray"}

[]{#last-exc-global}[global variable for last
exception](#last-exc-global-note)

[*none*]{style="color: gray"}

[*last exception:* sys.exc\_info()\[1\]]{style="color: gray"}

[*none*]{style="color: gray"}

[*last exception:* \$!]{style="color: gray"}\
[*backtrace array of exc.:* \$@]{style="color: gray"}\
[*exit status of child:* \$?]{style="color: gray"}

[]{#def-exc}[define exception](#def-exc-note)

function Bam(msg) {\
[  ]{style="white-space: pre-wrap;"}this.message = msg;\
}\
\
Bam.prototype = new Error;

class Bam(Exception):\
[  ]{style="white-space: pre-wrap;"}def
[\_\_init\_\_]{style="white-space: pre-wrap;"}(self):\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}super(Bam,
self).[\_\_init\_\_]{style="white-space: pre-wrap;"}(\'bam!\')

class Bam extends Exception\
{\
[  ]{style="white-space: pre-wrap;"}function
[\_\_]{style="white-space: pre-wrap;"}construct()\
[  ]{style="white-space: pre-wrap;"}{\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}parent::[\_\_]{style="white-space: pre-wrap;"}construct(\"bam!\");\
[  ]{style="white-space: pre-wrap;"}}\
}

class Bam \< Exception\
[  ]{style="white-space: pre-wrap;"}def initialize\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}super(\"bam!\")\
[  ]{style="white-space: pre-wrap;"}end\
end

[]{#handle-exc}[handle exception](#handle-exc-note)

try {\
[  ]{style="white-space: pre-wrap;"}throw new Bam(\"bam!\");\
} catch (e) {\
[  ]{style="white-space: pre-wrap;"}if (e instanceof Bam) {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}console.log(e.message);\
[  ]{style="white-space: pre-wrap;"}}\
[  ]{style="white-space: pre-wrap;"}else {\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}throw
e;\
[  ]{style="white-space: pre-wrap;"}}\
}

try:\
[  ]{style="white-space: pre-wrap;"}raise Bam()\
except Bam as e:\
[  ]{style="white-space: pre-wrap;"}print(e)

try {\
[  ]{style="white-space: pre-wrap;"}throw new Bam;\
} catch (Bam \$e) {\
[  ]{style="white-space: pre-wrap;"}echo \$e-\>getMessage(), \"\\n\";\
}

begin\
[  ]{style="white-space: pre-wrap;"}raise Bam.new\
rescue Bam =\> e\
[  ]{style="white-space: pre-wrap;"}puts e.message\
end

[]{#finally-block}[finally block](#finally-block-note)\
[ ]{style="white-space: pre-wrap;"}

acquireResource();\
try {\
[  ]{style="white-space: pre-wrap;"}risky();\
} finally {\
[  ]{style="white-space: pre-wrap;"}releaseResource();\
}

acquire\_resource()\
try:\
[  ]{style="white-space: pre-wrap;"}risky()\
finally:\
[  ]{style="white-space: pre-wrap;"}release\_resource()

[*PHP 5.5:*]{style="color: gray"}\
acquire\_resource();\
try {\
[  ]{style="white-space: pre-wrap;"}risky();\
}\
finally {\
[  ]{style="white-space: pre-wrap;"}release\_resource();\
}

acquire\_resource\
begin\
[  ]{style="white-space: pre-wrap;"}risky\
ensure\
[  ]{style="white-space: pre-wrap;"}release\_resource\
end

[]{#threads}[threads](#threads-note)

node.js

python

php

ruby

[]{#start-thread}[start thread](#start-thread-note)\
[ ]{style="white-space: pre-wrap;"}

class sleep10(threading.Thread):\
[  ]{style="white-space: pre-wrap;"}def run(self):\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}time.sleep(10)\
\
thr = sleep10()\
thr.start()

thr = Thread.new { sleep 10 }

[]{#wait-on-thread}[wait on thread](#wait-on-thread-note)\
[ ]{style="white-space: pre-wrap;"}

thr.join()

thr.join

[]{#sleep}[sleep](#sleep-note)

import time\
\
time.sleep(0.5)

[\# a float argument will be truncated\
\# to an integer:]{style="color: gray"}\
sleep(1);

sleep(0.5)

[]{#timeout}[timeout](#timeout-note)

import signal, time\
\
class Timeout(Exception): pass\
\
def timeout\_handler(signo, fm):\
[  ]{style="white-space: pre-wrap;"}raise Timeout()\
\
signal.signal(signal.SIGALRM,\
[  ]{style="white-space: pre-wrap;"}timeout\_handler)\
\
try:\
[  ]{style="white-space: pre-wrap;"}signal.alarm(5)\
[  ]{style="white-space: pre-wrap;"}might\_take\_too\_long()\
except Timeout:\
[  ]{style="white-space: pre-wrap;"}pass\
signal.alarm(0)

[*use* set\_time\_limit *to limit execution time of the entire script;
use* stream\_set\_timeout *to limit time spent reading from a stream
opened with* fopen *or* fsockopen]{style="color: gray"}

require \'timeout\'\
\
begin\
[  ]{style="white-space: pre-wrap;"}Timeout.timeout(5) do\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}might\_take\_too\_long\
[  ]{style="white-space: pre-wrap;"}end\
rescue Timeout::Error\
end

[[\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_]{style="white-space: pre-wrap;"}]{style="color: #efefef"}

[[\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_]{style="white-space: pre-wrap;"}]{style="color: #efefef"}

[[\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_]{style="white-space: pre-wrap;"}]{style="color: #efefef"}

[[\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_]{style="white-space: pre-wrap;"}]{style="color: #efefef"}

**[sheet two](/scripting2):** [streams](/scripting2#streams) \|
[asynchronous events](/scripting2#async) \| [files](/scripting2#file) \|
[directories](/scripting2#directories) \| [processes and
environment](/scripting2#processes-environment) \| [option
parsing](/scripting2#option-parsing) \| [libraries and
namespaces](/scripting2#libraries-namespaces) \|
[objects](/scripting2#objects) \| [inheritance and
polymorphism](/scripting2#inheritance-polymorphism) \|
[reflection](/scripting2#reflection) \| [net and
web](/scripting2#net-web) \| [gui](/scripting2#gui) \|
[databases](/scripting2#databases) \| [unit
tests](/scripting2#unit-tests) \|
[logging](/scripting2#logging-profiling) \|
[debugging](/scripting2#debugging-profiling)

[]{#version-note}

[Version](#version) {#toc0}
===================

[]{#version-used-note}

[version used](#version-used) {#toc1}
-----------------------------

The versions used for testing code in the reference sheet.

[]{#version-note}

[show version](#version) {#toc2}
------------------------

How to get the version.

**php:**

The function `phpversion()` will return the version number as a string.

**python:**

The following function will return the version number as a string:

::: {.code}
    import platform

    platform.python_version()
:::

**ruby:**

Also available in the global constant `RUBY_VERSION`.

[]{#implicit-prologue-note}

[implicit prologue](#implicit-prologue) {#toc3}
---------------------------------------

Code which examples in the sheet assume to have already been executed.

**javascript:**

`underscore.js` adds some convenience functions as attributes of an
object which is normally stored in the underscore `_` variable. E.g.:

::: {.code}
    _.map([1, 2, 3], function(n){ return n * n; });
:::

[cdnjs](http://cdnjs.com/libraries/underscore.js) hosts underscore.js
and other JavaScript libraries for situations where it is inconvenient
to have the webserver host the libraries.

When using `underscore.js` with the Node REPL, there is a conflict,
since the Node REPL uses the underscore `_` variable to store the result
of the last evaluation.

::: {.code}
    $ npm install underscore

    $ node

    > var us = require('underscore'); _

    > us.keys({"one": 1, "two": 2});
    [ 'one', 'two' ]
:::

**php:**

The `mbstring` package adds UTF-8 aware string functions with `mb_`
prefixes.

**python:**

We assume that `os`, `re`, and `sys` are always imported.

[]{#grammar-execution-note}

[Grammar and Execution](#grammar-execution) {#toc4}
===========================================

[]{#interpreter-note}

[interpreter](#interpreter) {#toc5}
---------------------------

The customary name of the interpreter and how to invoke it.

**php:**

`php -f` will only execute portions of the source file within a \<?php
[*php code*]{style="color: gray"} ?\> tag as php code. Portions of the
source file outside of such tags is not treated as executable code and
is echoed to standard out.

If short tags are enabled, then php code can also be placed inside \<?
[*php code*]{style="color: gray"} ?\> and \<?= [*php
code*]{style="color: gray"} ?\> tags.

\<?= [*php code*]{style="color: gray"} ?\> is identical to \<?php echo
[*php code*]{style="color: gray"} ?\>.

[]{#repl-note}

[repl](#repl) {#toc6}
-------------

The customary name of the repl.

**php:**

The `php -a` REPL does not save or display the result of an expression.

**python:**

The python repl saves the result of the last statement in
[\_]{style="white-space: pre-wrap;"}.

**ruby:**

`irb` saves the result of the last statement in
[\_]{style="white-space: pre-wrap;"}.

[]{#cmd-line-program-note}

[command line program](#cmd-line-program) {#toc7}
-----------------------------------------

How to pass the code to be executed to the interpreter as a command line
argument.

[]{#block-delimiters-note}

[block delimiters](#block-delimiters) {#toc8}
-------------------------------------

How blocks are delimited.

**python:**

Python blocks begin with a line that ends in a colon. The block ends
with the first line that is not indented further than the initial line.
Python raises an IndentationError if the statements in the block that
are not in a nested block are not all indented the same. Using tabs in
Python source code is unrecommended and many editors replace them
automatically with spaces. If the Python interpreter encounters a tab,
it is treated as 8 spaces.

The python repl switches from a `>>>` prompt to a ... prompt inside a
block. A blank line terminates the block.

Colons are also used to separate keys from values in dictionary literals
and in sequence slice notation.

**ruby:**

Curly brackets {} delimit blocks. A matched curly bracket pair can be
replaced by the `do` and `end` keywords. By convention curly brackets
are used for one line blocks.

The `end` keyword also terminates blocks started by `def`, `class`, or
`module`.

Curly brackets are also used for hash literals, and the \#{ } notation
is used to interpolate expressions into strings.

[]{#statement-separator-note}

[statement separator](#statement-separator) {#toc9}
-------------------------------------------

How the parser determines the end of a statement.

**php:**

Inside braces statements must be terminated by a semicolon. The
following causes a parse error:

::: {.code}
    <? if (true) { echo "true" } ?>
:::

The last statement inside `<?= ?>` or `<? ?>` tags does not need to be
semicolon terminated, however. The following code is legal:

::: {.code}
    <?= $a = 1 ?>
    <? echo $a ?>
:::

**python:**

Newline does not terminate a statement when:

-   inside parens
-   inside list \[\] or dictionary {} literals

Python single quote \'\' and double quote \"\" strings cannot contain
newlines except as the two character escaped form \\n. Putting a newline
in these strings results in a syntax error. There is however a
multi-line string literal which starts and ends with three single quotes
\'\'\' or three double quotes: \"\"\".

A newline that would normally terminate a statement can be escaped with
a backslash.

**ruby:**

Newline does not terminate a statement when:

-   inside single quotes \'\', double quotes \"\", backticks \`\`, or
    parens ()
-   after an operator such as + or , that expects another argument

Ruby permits newlines in array \[\] or hash literals, but only after a
comma , or associator =\>. Putting a newline before the comma or
associator results in a syntax error.

A newline that would normally terminate a statement can be escaped with
a backslash.

[]{#source-code-encoding-note}

[source code encoding](#source-code-encoding) {#toc10}
---------------------------------------------

How to identify the character encoding for a source code file.

Setting the source code encoding makes it possible to safely use
non-ASCII characters in string literals and regular expression literals.

[]{#eol-comment-note}

[end-of-line comment](#eol-comment) {#toc11}
-----------------------------------

How to create a comment that ends at the next newline.

[]{#multiple-line-comment-note}

[multiple line comment](#multiple-line-comment) {#toc12}
-----------------------------------------------

How to comment out multiple lines.

**python:**

The triple single quote \'\'\' and triple double quote \"\"\" syntax is
a syntax for string literals.

[]{#var-expr-note}

[Variables and Expressions](#var-expr) {#toc13}
======================================

[]{#local-var-note}

[local variable](#local-var) {#toc14}
----------------------------

How to declare variables which are local to the scope defining region
which immediately contain them.

**php:**

Variables do not need to be declared and there is no syntax for
declaring a local variable. If a variable with no previous reference is
accessed, its value is *NULL*.

**python:**

A variable is created by assignment if one does not already exist. If
the variable is inside a function or method, then its scope is the body
of the function or method. Otherwise it is a global.

**ruby:**

Variables are created by assignment. If the variable does not have a
dollar sign (\$) or ampersand (@) as its first character then its scope
is scope defining region which most immediately contains it.

A lower case name can refer to a local variable or method. If both are
defined, the local variable takes precedence. To invoke the method make
the receiver explicit: e.g. self.*name*. However, outside of class and
modules local variables hide functions because functions are private
methods in the class *Object*. Assignment to *name* will create a local
variable if one with that name does not exist, even if there is a method
*name*.

[]{#file-scope-var-note}

[file scope variable](#file-scope-var) {#toc15}
--------------------------------------

How to define a variable with scope bound by the source file.

[]{#global-var-note}

[global variable](#global-var) {#toc16}
------------------------------

How to declare and access a variable with global scope.

**php:**

A variable is global if it is used at the top level (i.e. outside any
function definition) or if it is declared inside a function with the
*global* keyword. A function must use the *global* keyword to access the
global variable.

**python:**

A variable is global if it is defined at the top level of a file (i.e.
outside any function definition). Although the variable is global, it
must be imported individually or be prefixed with the module name prefix
to be accessed from another file. To be accessed from inside a function
or method it must be declared with the *global* keyword.

**ruby:**

A variable is global if it starts with a dollar sign: \$.

[]{#const-note}

[constant](#const) {#toc17}
------------------

How to declare a constant.

**php:**

A constant can be declared inside a class:

::: {.code}
    class Math {
      const pi = 3.14;
    }
:::

Refer to a class constant like this:

::: {.code}
    Math::pi
:::

**ruby:**

Capitalized variables contain constants and class/module names. By
convention, constants are all caps and class/module names are camel
case. The ruby interpreter does not prevent modification of constants,
it only gives a warning. Capitalized variables are globally visible, but
a full or relative namespace name must be used to reach them: e.g.
Math::PI.

[]{#assignment-note}

[assignment](#assignment) {#toc18}
-------------------------

How to assign a value to a variable.

**python:**

If the variable on the left has not previously been defined in the
current scope, then it is created. This may hide a variable in a
containing scope.

Assignment does not return a value and cannot be used in an expression.
Thus, assignment cannot be used in a conditional test, removing the
possibility of using assignment (=) when an equality test (==) was
intended. Assignments can nevertheless be chained to assign a value to
multiple variables:

::: {.code}
    a = b = 3
:::

**ruby:**

Assignment operators have right precedence and evaluate to the right
argument, so they can be chained. If the variable on the left does not
exist, then it is created.

[]{#parallel-assignment-note}

[parallel assignment](#parallel-assignment) {#toc19}
-------------------------------------------

How to assign values to variables in parallel.

**python:**

The r-value can be a list or tuple:

::: {.code}
    nums = [1, 2, 3]
    a, b, c = nums
    more_nums = (6, 7, 8)
    d, e, f = more_nums
:::

Nested sequences of expression can be assigned to a nested sequences of
l-values, provided the nesting matches. This assignment will set a to 1,
b to 2, and c to 3:

::: {.code}
    (a,[b,c]) = [1,(2,3)]
:::

This assignment will raise a `TypeError`:

::: {.code}
    (a,(b,c)) = ((1,2),3)
:::

In Python 3 the splat operator `*` can be used to collect the remaining
right side elements in a list:

::: {.code}
    x, y, *z = 1, 2        # assigns [] to z
    x, y, *z = 1, 2, 3     # assigns [3] to z
    x, y, *z = 1, 2, 3, 4  # assigns [3, 4] to z
:::

**ruby:**

The r-value can be an array:

::: {.code}
    nums = [1, 2, 3]
    a,b,c = nums
:::

[]{#swap-note}

[swap](#swap) {#toc20}
-------------

How to swap the values held by two variables.

[]{#compound-assignment-note}

[compound assignment](#compound-assignment) {#toc21}
-------------------------------------------

Compound assignment operators mutate a variable, setting it to the value
of an operation which takes the previous value of the variable as an
argument.

If `<OP>` is a binary operator and the language has the compound
assignment operator `<OP>=`, then the following are equivalent:

::: {.code}
    x <OP>= y
    x = x <OP> y
:::

The compound assignment operators are displayed in this order:

*First row:* arithmetic operator assignment: addition, subtraction,
multiplication, (float) division, integer division, modulus, and
exponentiation.\
*Second row:* string concatenation assignment and string replication
assignment\
*Third row:* logical operator assignment: and, or, xor\
*Fourth row:* bit operator assignment: left shift, right shift, and, or,
xor.

**python:**

Python compound assignment operators do not return a value and hence
cannot be used in expressions.

[]{#incr-decr-note}

[increment and decrement](#incr-decr) {#toc22}
-------------------------------------

The C-style increment and decrement operators can be used to increment
or decrement values. They return values and thus can be used in
expressions. The prefix versions return the value in the variable after
mutation, and the postfix version return the value before mutation.

Incrementing a value two or more times in an expression makes the order
of evaluation significant:

::: {.code}
    x = 1;
    foo(++x, ++x); // foo(2, 3) or foo(3, 2)?

    x = 1;
    y = ++x/++x;  // y = 2/3 or y = 3/2?
:::

Python avoids the problem by not having an in-expression increment or
decrement.

Ruby mostly avoids the problem by providing a non-mutating increment and
decrement. However, here is a Ruby expression which is dependent on
order of evaluation:

::: {.code}
    x = 1
    y = (x += 1)/(x += 1)
:::

**php:**

The increment and decrement operators also work on strings. There are
postfix versions of these operators which evaluate to the value before
mutation:

::: {.code}
    $x = 1;
    $x++;
    $x--;
:::

**ruby:**

The Integer class defines `succ`, `pred`, and `next`, which is a synonym
for `succ`.

The String class defines `succ`, `succ!`, `next`, and `next!`. `succ!`
and `next!` mutate the string.

[]{#null-note}

[null](#null) {#toc23}
-------------

The null literal.

[]{#null-test-note}

[null test](#null-test) {#toc24}
-----------------------

How to test if a variable contains null.

**php:**

*\$v == NULL* does not imply that *\$v* is *NULL*, since any comparison
between *NULL* and a falsehood will return true. In particular, the
following comparisons are true:

::: {.code}
    $v = NULL;
    if ($v == NULL) { echo "true"; }

    $v = 0;
    if ($v == NULL) { echo "sadly true"; }

    $v = '';
    if ($v == NULL) { echo "sadly true"; }
:::

[]{#undef-var-note}

[undefined variable](#undef-var) {#toc25}
--------------------------------

The result of attempting to access an undefined variable.

**python:**

Because a class can implement an `eq` method to change the
implementation of `v == None`, the expression can be `True` when `v` is
not `None`.

**php:**

PHP does not provide the programmer with a mechanism to distinguish an
undefined variable from a variable which has been set to NULL.

[A test](https://gist.github.com/1157508) showing that `isset` is the
logical negation of `is_null`.

**python:**

How to test if a variable is defined:

::: {.code}
    not_defined = False
    try: v
    except NameError:
      not_defined = True
:::

**ruby:**

How to test if a variable is defined:

::: {.code}
    ! defined?(v)
:::

[]{#conditional-expr-note}

[conditional expression](#conditional-expr) {#toc26}
-------------------------------------------

How to write a conditional expression. A ternary operator is an operator
which takes three arguments. Since

[*condition*]{style="color: gray"} ? [*true value*]{style="color: gray"}
: [*false value*]{style="color: gray"}

is the only ternary operator in C, it is unambiguous to refer to it as
*the* ternary operator.

**python:**

The Python conditional expression comes from Algol.

**ruby:**

The Ruby `if` statement is also an expression:

::: {.code}
    x = if x > 0
      x
    else
      -x
    end
:::

[]{#arithmetic-logic-note}

[Arithmetic and Logic](#arithmetic-logic) {#toc27}
=========================================

[]{#true-false-note}

[true and false](#true-false) {#toc28}
-----------------------------

Literals for the booleans.

These are the return values of the relational operators.

**php:**

Any identifier which matches TRUE case-insensitive can be used for the
TRUE boolean. Similarly for FALSE.

In general, PHP variable names are case-sensitive, but function names
are case-insensitive.

When converted to a string for display purposes, TRUE renders as \"1\"
and FALSE as \"\". The equality tests `TRUE == 1` and `FALSE == ""`
evaluate as TRUE but the equality tests `TRUE === 1` and `FALSE === ""`
evaluate as FALSE.

[]{#falsehoods-note}

[falsehoods](#falsehoods) {#toc29}
-------------------------

Values which behave like the false boolean in a conditional context.

Examples of conditional contexts are the conditional clause of an `if`
statement and the test of a `while` loop.

**python:**

Whether a object evaluates to True or False in a boolean context can be
customized by implementing a
[\_\_nonzero\_\_]{style="white-space: pre-wrap;"} (Python 2) or
[\_\_bool\_\_]{style="white-space: pre-wrap;"} (Python 3) instance
method for the class.

[]{#logical-op-note}

[logical operators](#logical-op) {#toc30}
--------------------------------

Logical and, or, and not.

**php, ruby:**

&& and [\|\|]{style="white-space: pre-wrap;"} have higher precedence
than assignment, compound assignment, and the ternary operator (?:),
which have higher precedence than *and* and *or*.

[]{#relational-op-note}

[relational operators](#relational-op) {#toc31}
--------------------------------------

Equality, inequality, greater than, less than, greater than or equal,
less than or equal.

**php:**

Most of the relational operators will convert a string to a number if
the other operand is a number. Thus 0 == \"0\" is true. The operators
=== and !== do not perform this conversion, so 0 === \"0\" is false.

**python:**

Relational operators can be chained. The following expressions evaluate
to true:

::: {.code}
    1 < 2 < 3
    1 == 1 != 2
:::

In general if *A~i~* are expressions and *op~i~* are relational
operators, then

[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}`A1 op1 A2 op2 A3 … An opn An+1`

is true if and only if each of the following is true

[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}`A1 op1 A2`\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}`A2 op2 A3`\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}...\
[  ]{style="white-space: pre-wrap;"}[  ]{style="white-space: pre-wrap;"}`An opn An+1`

[]{#min-max-note}

[min and max](#min-max) {#toc32}
-----------------------

How to get the min and max.

[]{#arith-op-note}

[arithmetic operators](#arith-op) {#toc33}
---------------------------------

The operators for addition, subtraction, multiplication, float division,
integer division, modulus, and exponentiation.

[]{#int-div-note}

[integer division](#int-div) {#toc34}
----------------------------

How to get the integer quotient of two integers.

[]{#divmod-note}

[divmod](#divmod) {#toc35}
-----------------

How to get the quotient and remainder with single function call.

[]{#int-div-zero-note}

[integer division by zero](#int-div-zero) {#toc36}
-----------------------------------------

What happens when an integer is divided by zero.

[]{#float-div-note}

[float division](#float-div) {#toc37}
----------------------------

How to perform floating point division, even if the operands might be
integers.

[]{#float-div-zero-note}

[float division by zero](#float-div-zero) {#toc38}
-----------------------------------------

What happens when a float is divided by zero.

[]{#power-note}

[power](#power) {#toc39}
---------------

How to get the value of a number raised to a power.

[]{#sqrt-note}

[sqrt](#sqrt) {#toc40}
-------------

The square root function.

[]{#sqrt-negative-one-note}

[sqrt -1](#sqrt-negative-one) {#toc41}
-----------------------------

The result of taking the square root of negative one.

[]{#transcendental-func-note}

[transcendental functions](#transcendental-func) {#toc42}
------------------------------------------------

Some mathematical functions. Trigonometric functions are in radians
unless otherwise noted. Logarithms are natural unless otherwise noted.

**python:**

Python also has *math.log10*. To compute the log of *x* for base *b*,
use:

::: {.code}
    math.log(x)/math.log(b)
:::

**ruby:**

Ruby also has *Math.log2*, *Math.log10*. To compute the log of *x* for
base *b*, use

::: {.code}
    Math.log(x)/Math.log(b)
:::

[]{#transcendental-const-note}

[transcendental constants](#transcendental-const) {#toc43}
-------------------------------------------------

Constants for π and Euler\'s constant.

[]{#float-truncation-note}

[float truncation](#float-truncation) {#toc44}
-------------------------------------

How to truncate a float to the nearest integer towards zero; how to
round a float to the nearest integer; how to find the nearest integer
above a float; how to find the nearest integer below a float; how to
take the absolute value.

[]{#abs-val-note}

[absolute value](#abs-val) {#toc45}
--------------------------

How to get the absolute value of a number.

[]{#int-overflow-note}

[integer overflow](#int-overflow) {#toc46}
---------------------------------

What happens when the largest representable integer is exceeded.

[]{#float-overflow-note}

[float overflow](#float-overflow) {#toc47}
---------------------------------

What happens when the largest representable float is exceeded.

[]{#rational-note}

[rational numbers](#rational) {#toc48}
-----------------------------

How to create rational numbers and get the numerator and denominator.

**ruby:**

Require the library *mathn* and integer division will yield rationals
instead of truncated integers.

[]{#complex-note}

[complex numbers](#complex) {#toc49}
---------------------------

**python:**

Most of the functions in *math* have analogues in *cmath* which will
work correctly on complex numbers.

[]{#random-note}

[random integer, uniform float, normal float](#random) {#toc50}
------------------------------------------------------

How to generate a random integer between 0 and 99, include, float
between zero and one in a uniform distribution, or a float in a normal
distribution with mean zero and standard deviation one.

[]{#random-seed-note}

[set random seed, get and restore seed](#random-seed) {#toc51}
-----------------------------------------------------

How to set the random seed; how to get the current random seed and later
restore it.

All the languages in the sheet set the seed automatically to a value
that is difficult to predict. The Ruby MRI interpreter uses the current
time and process ID, for example. As a result there is usually no need
to set the seed.

Setting the seed to a hardcoded value yields a random but repeatable
sequence of numbers. This can be used to ensure that unit tests which
cover code using random numbers doesn\'t intermittently fail.

The seed is global state. If multiple functions are generating random
numbers then saving and restoring the seed may be necessary to produce a
repeatable sequence.

[]{#bit-op-note}

[bit operators](#bit-op) {#toc52}
------------------------

The bit operators for left shift, right shift, and, inclusive or,
exclusive or, and negation.

[]{#binary-octal-hex-literals-note}

[binary, octal, and hex literals](#binary-octal-hex-literals) {#toc53}
-------------------------------------------------------------

Binary, octal, and hex integer literals

[]{#radix-note}

[radix](#radix) {#toc54}
---------------

How to convert integers to strings of digits of a given base. How to
convert such strings into integers.

**python**

Python has the functions `bin`, `oct`, and `hex` which take an integer
and return a string encoding the integer in base 2, 8, and 16.

::: {.code}
    bin(42)
    oct(42)
    hex(42)
:::

[]{#strings-note}

[Strings](#strings) {#toc55}
===================

[]{#str-type-note}

[string type](#str-type) {#toc56}
------------------------

The type for a string of Unicode characters.

**php:**

PHP assumes all strings have single byte characters.

**python:**

In Python 2.7 the `str` type assumes single byte characters. A separate
`unicode` type is available for working with Unicode strings.

In Python 3 the `str` type supports multibtye characters and the
`unicode` type has been removed.

There is a mutable `bytearray` type and an immutable `bytes` type for
working with sequences of bytes.

**ruby:**

The `String` type supports multibtye characters. All strings have an
explicit `Encoding`.

[]{#str-literal-note}

[string literal](#str-literal) {#toc57}
------------------------------

The syntax for string literals.

**python:**

String literals may have a `u` prefix

::: {.code}
    u'lorem ipsum'
    u"lorem ipsum"
    u'''lorem
    ipsum'''
    u"""lorem
    ipsum"""
:::

In Python 3, these are identical to literals without the `u` prefix.

In Python 2, these create `unicode` strings instead of `str` strings.
Since the Python 2 `unicode` type corresponds to the Python 3 `str`
type, portable code will use the `u` prefix.

**ruby:**

How to specify custom delimiters for single and double quoted strings.
These can be used to avoid backslash escaping. If the left delimiter is
(, \[, or { the right delimiter must be ), \], or }, respectively.

::: {.code}
    s1 = %q(lorem ipsum)
    s2 = %Q(#{s1} dolor sit amet)
:::

[]{#newline-in-str-literal-note}

[newline in literal](#newline-in-str-literal) {#toc58}
---------------------------------------------

Whether newlines are permitted in string literals.

**python:**

Newlines are not permitted in single quote and double quote string
literals. A string can continue onto the following line if the last
character on the line is a backslash. In this case, neither the
backslash nor the newline are taken to be part of the string.

Triple quote literals, which are string literals terminated by three
single quotes or three double quotes, can contain newlines:

::: {.code}
    '''This is
    two lines'''

    """This is also
    two lines"""
:::

[]{#str-literal-esc-note}

[literal escapes](#str-literal-esc) {#toc59}
-----------------------------------

Backslash escape sequences for inserting special characters into string
literals.

unrecognized backslash escape sequence

double quote

single quote

JavaScript

PHP

preserve backslash

preserve backslash

Python

preserve backslash

preserve backslash

Ruby

drop backslash

preserve backslash

**python:**

When string literals have an `r` or `R` prefix there are no backslash
escape sequences and any backslashes thus appear in the created string.
The delimiter can be inserted into a string if it is preceded by a
backslash, but the backslash is also inserted. It is thus not possible
to create a string with an `r` or `R` prefix that ends in a backslash.
The `r` and `R` prefixes can be used with single or double quotes:

::: {.code}
    r'C:\Documents and Settings\Admin'
    r"C:\Windows\System32"
:::

The \\u[*hhhh*]{style="color: gray"} escapes are also available inside
Python 2 Unicode literals. Unicode literals have a *u* prefiix:

::: {.code}
    u'lambda: \u03bb'
:::

This syntax is also available in Python 3.3, but not Python 3.2. In
Python 3.3 it creates a string of type `str` which has the same features
as the `unicode` type of Python 2.7.

[]{#here-doc-note}

[here document](#here-doc) {#toc60}
--------------------------

Here documents are strings terminated by a custom identifier. They
perform variable substitution and honor the same backslash escapes as
double quoted strings.

**python:**

Triple quotes honor the same backslash escape sequences as regular
quotes, so triple quotes can otherwise be used like here documents:

::: {.code}
    s = '''here document
    there computer
    '''
:::

**ruby:**

Put the customer identifier in single quotes to prevent variable
interpolation and backslash escape interpretation:

::: {.code}
    s = <<'EOF'
    Ruby code uses #{var} type syntax
    to interpolate variables into strings.
    EOF
:::

[]{#var-interpolation-note}

[variable interpolation](#var-interpolation) {#toc61}
--------------------------------------------

How to interpolate variables into strings.

**python:**

The f\'1 + 1 = {1 + 1}\' and f\"1 + 1 = {1 + 1}\" literals, which
support variable interpolation and expression interpolation, are new in
Python 3.6.

`str.format` will take named or positional parameters. When used with
named parameters `str.format` can mimic the variable interpolation
feature of the other languages.

A selection of variables in scope can be passed explicitly:

::: {.code}
    count = 3
    item = 'ball'
    print('{count} {item}s'.format(
      count=count,
      item=item))
:::

Python 3 has `format_map` which accepts a `dict` as an argument:

::: {.code}
    count = 3
    item = 'ball'
    print('{count} {item}s'.format_map(locals()))
:::

[]{#expr-interpolation-note}

[expression interpolation](#expr-interpolation) {#toc62}
-----------------------------------------------

How to interpolate the result of evaluating an expression into a string.

[]{#format-str-note}

[format string](#format-str) {#toc63}
----------------------------

How to create a string using a printf style format.

**python:**

The % operator will interpolate arguments into printf-style format
strings.

The `str.format` with positional parameters provides an alternative
format using curly braces {0}, {1}, ... for replacement fields.

The curly braces are escaped by doubling:

::: {.code}
    'to insert parameter {0} into a format, use {{{0}}}'.format(3)
:::

If the replacement fields appear in sequential order and aren\'t
repeated, the numbers can be omitted:

::: {.code}
    'lorem {} {} {}'.format('ipsum', 13, 3.7)
:::

[]{#mutable-str-note}

[are strings mutable?](#mutable-str) {#toc64}
------------------------------------

Are strings mutable?

[]{#copy-str-note}

[copy string](#copy-str) {#toc65}
------------------------

How to copy a string such that changes to the original do not modify the
copy.

[]{#str-concat-note}

[concatenate](#str-concat) {#toc66}
--------------------------

The string concatenation operator.

[]{#str-replicate-note}

[replicate](#str-replicate) {#toc67}
---------------------------

The string replication operator.

[]{#translate-case-note}

[translate case](#translate-case) {#toc68}
---------------------------------

How to put a string into all caps or all lower case letters.

[]{#capitalize-note}

[capitalize](#capitalize) {#toc69}
-------------------------

How to capitalize a string and the words in a string.

The examples lowercase non-initial letters.

**php:**

How to define a UTF-8 aware version of `ucfirst`. This version also puts
the rest of the string in lowercase:

::: {.code}
    function mb_ucfirst($string, $encoding = "UTF-8")
    {
        $strlen = mb_strlen($string, $encoding);
        $firstChar = mb_substr($string, 0, 1, $encoding);
        $then = mb_substr(mb_strtolower($string), 1, $strlen - 1, $encoding);
        return mb_strtoupper($firstChar, $encoding) . $then;
    }
:::

**ruby:**

Rails monkey patches the `String` class with the `titleize` method for
capitalizing the words in a string.

[]{#trim-note}

[trim](#trim) {#toc70}
-------------

How to remove whitespace from the ends of a string.

[]{#pad-note}

[pad](#pad) {#toc71}
-----------

How to pad the edge of a string with spaces so that it is a prescribed
length.

[]{#num-to-str-note}

[number to string](#num-to-str) {#toc72}
-------------------------------

How to convert numeric data to string data.

[]{#fmt-float-note}

[format float](#fmt-float) {#toc73}
--------------------------

How to control the number of digits in a float when converting it to a
string.

**python:**

The number after the decimal controls the number of digits after the
decimal:

::: {.code}
    >>> '%.2f' % math.pi
    '3.14'
:::

The number after the decimal controls the total number of digits:

::: {.code}
    >>> '{:.3}'.format(math.pi)
    '3.14'
:::

[]{#str-to-num-note}

[string to number](#str-to-num) {#toc74}
-------------------------------

How to convert string data to numeric data.

**php:**

PHP converts a scalar to the desired type automatically and does not
raise an error if the string contains non-numeric data. If the start of
the string is not numeric, the string evaluates to zero in a numeric
context.

**python:**

float and int raise an error if called on a string and any part of the
string is not numeric.

**ruby:**

to\_i and to\_f always succeed on a string, returning the numeric value
of the digits at the start of the string, or zero if there are no
initial digits.

[]{#str-join-note}

[string join](#str-join) {#toc75}
------------------------

How to concatenate the elements of an array into a string with a
separator.

[]{#split-note}

[split](#split) {#toc76}
---------------

How to split a string containing a separator into an array of
substrings.

See also [scan](#scan).

**python:**

`str.split()` takes simple strings as delimiters; use `re.split()` to
split on a regular expression:

::: {.code}
    re.split('\s+', 'do re mi fa')
    re.split('\s+', 'do re mi fa', 1)
:::

[]{#split-in-two-note}

[split in two](#split-in-two) {#toc77}
-----------------------------

How to split a string in two.

**javascript:**

A regular expression is probably the best method for splitting a string
in two:

::: {.code}
    var m = /^([^ ]+) (.+)/.exec("do re mi");
    var first = m[1];
    var rest = m[2];
:::

This technique works when the delimiter is a fixed string:

::: {.code}
    var a = "do re mi".split(" ");
    var first = a[0];
    var rest = a.splice(1).join(" ");
:::

**python:**

Methods for splitting a string into three parts using the first or last
occurrence of a substring:

::: {.code}
    'do re mi'.partition(' ')         # returns ('do', ' ', 're mi')
    'do re mi'.rpartition(' ')        # returns ('do re', ' ', 'mi')
:::

[]{#split-keep-delimiters-note}

[split and keep delimiters](#split-keep-delimiters) {#toc78}
---------------------------------------------------

How to split a string with the delimiters preserved as separate
elements.

[]{#prefix-suffix-test-note}

[prefix and suffix test](#prefix-suffix-test) {#toc79}
---------------------------------------------

How to test whether a string begins or ends with a substring.

[]{#str-len-note}

[length](#str-len) {#toc80}
------------------

How to get the length in characters of a string.

[]{#index-substr-note}

[index of substring](#index-substr) {#toc81}
-----------------------------------

How to find the index of the leftmost occurrence of a substring in a
string; how to find the index of the rightmost occurrence.

[]{#extract-substr-note}

[extract substring](#extract-substr) {#toc82}
------------------------------------

How to extract a substring from a string by index.

[]{#bytes-type-note}

[byte array type](#bytes-type) {#toc83}
------------------------------

The type for an array of bytes.

[]{#bytes-to-str-note}

[byte array to string](#bytes-to-str) {#toc84}
-------------------------------------

How to convert an array of bytes to a string of Unicode characters.

[]{#str-to-bytes-note}

[string to byte array](#str-to-bytes) {#toc85}
-------------------------------------

How to convert a string of Unicode characters to an array of bytes.

[]{#lookup-char-note}

[character lookup](#lookup-char) {#toc86}
--------------------------------

How to look up the character in a string at an index.

[]{#chr-ord-note}

[chr and ord](#chr-ord) {#toc87}
-----------------------

Converting characters to ASCII codes and back.

The languages in this reference sheet do not have character literals, so
characters are represented by strings of length one.

[]{#str-to-char-array-note}

[to array of characters](#str-to-char-array) {#toc88}
--------------------------------------------

How to split a string into an array of single character strings.

[]{#translate-char-note}

[translate characters](#translate-char) {#toc89}
---------------------------------------

How to apply a character mapping to a string.

**python:**

In Python 2, the string of lowercase letters is in `string.lowercase`
instead of `string.ascii_lowercase`.

In Python 2, the `maketrans` function is in the module `string` instead
of `str`.

[]{#delete-char-note}

[delete characters](#delete-char) {#toc90}
---------------------------------

How to remove all specified characters from a string; how to remove all
but the specified characters from a string.

[]{#squeeze-char-note}

[squeeze characters](#squeeze-char) {#toc91}
-----------------------------------

How to replace multiple adjacent occurrences of a character with a
single occurrence.

[]{#regexes-note}

[Regular Expressions](#regexes) {#toc92}
===============================

-   [PHP PCRE Regexes](http://php.net/manual/en/book.pcre.php)
-   Python re library: [2.7](http://docs.python.org/library/re.html),
    [3.1](http://docs.python.org/release/3.1.3/library/re.html)
-   [Ruby Regexp](http://www.ruby-doc.org/core/classes/Regexp.html)

Regular expressions or regexes are a way of specifying sets of strings.
If a string belongs to the set, the string and regex \"match\". Regexes
can also be used to parse strings.

The modern notation for regexes was introduced by Unix command line
tools in the 1970s. POSIX standardized the notation into two types:
extended regexes and the more archaic basic regexes. Perl regexes are
extended regexes augmented by new character class abbreviations and a
few other features introduced by the Perl interpreter in the 1990s. All
the languages in this sheet use Perl regexes.

Any string that doesn\'t contain regex metacharacters is a regex which
matches itself. The regex metacharacters are:
`[ ] . | ( ) * + ? { } ^ $ \`

**character classes: \[ \] .**

A character class is a set of characters in brackets: `[ ].` When used
in a regex it matches any character it contains.

Character classes have their own set of metacharacters: `^ - \ ]`

The `^` is only special when it is the first character in the character
class. Such a character class matches its complement; that is, any
character not inside the brackets. When not the first character the `^`
refers to itself.

The hyphen is used to specify character ranges: e.g. `0-9` or `A-Z`.
When the hyphen is first or last inside the brackets it matches itself.

The backslash can be used to escape the above characters or the terminal
character class delimiter: `]`. It can be used in character class
abbreviations or string backslash escapes.

The period `.` is a character class abbreviation which matches any
character except for newline. In all languages the period can be made to
match all characters. PHP uses the `m` modifier. Python uses the `re.M`
flag. Ruby uses the `s` modifier.

[]{#regex-char-class-abbrev}\
**character class abbreviations:**

  --------------------------------------------------------------------------------------------------------------------------------
  abbrev   name                                                                   character class
  -------- ---------------------------------------------------------------------- ------------------------------------------------
  \\d      digit                                                                  \[0-9\]

  \\D      nondigit                                                               \[\^0-9\]

  \\h      [*PHP:*]{style="color: gray"} horizontal whitespace character\         [*PHP:*]{style="color: gray"} \[ \\t\]\
           [*Ruby:*]{style="color: gray"} hex digit                               [*Ruby:*]{style="color: gray"} \[0-9a-fA-F\]

  \\H      [*PHP:*]{style="color: gray"} not a horizontal whitespace character\   [*PHP:*]{style="color: gray"} \[\^ \\t\]\
           [*Ruby:*]{style="color: gray"} not a hex digit                         [*Ruby:*]{style="color: gray"} \[\^0-9a-fA-F\]

  \\s      whitespace character                                                   \[ \\t\\r\\n\\f\]

  \\S      non whitespace character                                               \[\^ \\t\\r\\n\\f\]

  \\v      vertical whitespace character                                          \[\\r\\n\\f\]

  \\V      not a vertical whitespace character                                    \[\^\\r\\n\\f\]

  \\w      word character                                                         \[A-Za-z0-9\_\]

  \\W      non word character                                                     \[\^A-Za-z0-9\_\]
  --------------------------------------------------------------------------------------------------------------------------------

**alternation and grouping: \| ( )**

The vertical pipe \| is used for alternation and parens () for grouping.

A vertical pipe takes as its arguments everything up to the next
vertical pipe, enclosing paren, or end of string.

Parentheses control the scope of alternation and the quantifiers
described below. They are also used for capturing groups, which are the
substrings which matched parenthesized parts of the regular expression.
Each language numbers the groups and provides a mechanism for extracting
them when a match is made. A parenthesized subexpression can be removed
from the groups with this syntax: `(?:expr)`

**quantifiers: \* + ? { }**

As an argument quantifiers take the preceding regular character,
character class, or group. The argument can itself be quantified, so
that `^a{4}*$` matches strings with the letter a in multiples of 4.

  quantifier                             \# of occurrences of argument matched
  -------------------------------------- ---------------------------------------
  [\*]{style="white-space: pre-wrap;"}   zero or more, greedy
  \+                                     one or more, greedy
  ?                                      zero or one, greedy
  {m,n}                                  *m* to *n*, greedy
  {n}                                    exactly *n*
  {m,}                                   *m* or more, greedy
  {,n}                                   zero to *n*, greedy
  \*?                                    zero or more, lazy
  +?                                     one or more, lazy
  {m,n}?                                 *m* to *n*, lazy
  {m,}?                                  *m* or more, lazy
  {,n}?                                  zero to *n*, lazy

When there is a choice, greedy quantifiers will match the maximum
possible number of occurrences of the argument. Lazy quantifiers match
the minimum possible number.

**anchors: \^ \$**

  anchor   matches
  -------- --------------------------------------------------------------------------------------------------------------
  \^       beginning of a string. In Ruby or when *m* modifier is used also matches right side of a newline
  \$       end of a string. In Ruby or when *m* modifier is used also matches left side of a newline
  \\A      beginning of the string
  \\b      word boundary. In between a \\w and a \\W character or in between a \\w character and the edge of the string
  \\B      not a word boundary. In between two \\w characters or two \\W characters
  \\z      end of the string
  \\Z      end of the string unless it is a newline, in which case it matches the left side of the terminal newline

**escaping: \\**

To match a metacharacter, put a backslash in front of it. To match a
backslash use two backslashes.

**php:**

PHP 5.3 still supports the EREG engine, though the functions which use
it are deprecated. These include the `split` function and functions
which start with `ereg`. The preferred functions are `preg_split` and
the other functions with a `preg` prefix.

[]{#regex-literal-note}

[literal, custom delimited literal](#regex-literal) {#toc93}
---------------------------------------------------

The literal for a regular expression; the literal for a regular
expression with a custom delimiter.

**javascript:**

The constructor for a regular expression is:

::: {.code}
    var rx = RegExp("lorem|ipsum");
:::

**php:**

PHP regex literals are strings. The first character is the delimiter and
it must also be the last character. If the start delimiter is (, {, or
\[ the end delimiter must be ), }, or \], respectively.

Here are the signatures from the PHP manual for the preg functions used
in this sheet:

::: {.code}
    array preg_split ( string $pattern , string $subject [, int $limit = -1 [, int $flags = 0 ]] )

    int preg_match ( string $pattern , string $subject [, array &$matches [, int $flags = 0 [, int $offset = 0 ]]] )

    mixed preg_replace ( mixed $pattern , mixed $replacement , mixed $subject [, int $limit = -1 [, int &$count ]] )

    int preg_match_all ( string $pattern , string $subject [, array &$matches [, int $flags = PREG_PATTERN_ORDER [, int $offset = 0 ]]] )
:::

**python:**

Python does not have a regex literal, but the `re.compile` function can
be used to create regex objects.

Compiling regexes can always be avoided:

::: {.code}
    re.compile('\d{4}').search('1999')
    re.search('\d{4}', '1999')

    re.compile('foo').sub('bar', 'foo bar')
    re.sub('foo', 'bar', 'foo bar')

    re.compile('\w+').findall('do re me')
    re.findall('\w+', 'do re me')
:::

[]{#ascii-char-class-abbrev-note}

[ascii character class abbreviations](#ascii-char-class-abbrev) {#toc94}
---------------------------------------------------------------

The supported [character class abbreviations](#regex-char-class-abbrev).

Note that `\h` refers to horizontal whitespace (i.e. a space or tab) in
PHP and a hex digit in Ruby. Similarly `\H` refers to something that
isn\'t horizontal whitespace in PHP and isn\'t a hex digit in Ruby.

[]{#unicode-char-class-abbrev-note}

[unicode character class abbreviations](#unicode-char-class-abbrev) {#toc95}
-------------------------------------------------------------------

The supported character class abbreviations for sets of Unicode
characters.

Each Unicode character belongs to one of these major categories:

  --- -------------
  C   Other
  L   Letter
  M   Mark
  N   Number
  P   Punctuation
  S   Symbol
  Z   Separator
  --- -------------

Each major category is subdivided into multiple minor categories. Each
minor category has a two letter code, where the first letter is the
major category. For example, `Nd` is \"Number, decimal digit\".

Download
[UnicodeData.txt](http://www.unicode.org/Public/UNIDATA/UnicodeData.txt)
to find out which major and minor category and character belongs to.

[]{#regex-anchors-note}

[anchors](#regex-anchors) {#toc96}
-------------------------

The supported anchors.

[]{#regex-test-note}

[match test](#regex-test) {#toc97}
-------------------------

How to test whether a string matches a regular expression.

**python:**

The `re.match` function returns true only if the regular expression
matches the beginning of the string. `re.search` returns true if the
regular expression matches any substring of the of string.

**ruby:**

`match` is a method of both `Regexp` and `String` so can match with both

::: {.code}
    /1999/.match("1999")
:::

and

::: {.code}
    "1999".match(/1999/)
:::

When variables are involved it is safer to invoke the `Regexp` method
because string variables are more likely to contain `nil`.

[]{#case-insensitive-regex-note}

[case insensitive match test](#case-insensitive-regex) {#toc98}
------------------------------------------------------

How to perform a case insensitive match test.

[]{#regex-modifiers-note}

[modifiers](#regex-modifiers) {#toc99}
-----------------------------

Modifiers that can be used to adjust the behavior of a regular
expression.

The lists are not comprehensive. For all languages except Ruby there are
additional modifiers.

  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  modifier   behavior
  ---------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  e          [*PHP:*]{style="color: gray"} when used with preg\_replace, the replacement string, after backreferences are substituted, is eval\'ed as PHP code and the result is used as the replacement.

  g          [*JavaScript:*]{style="color: gray"} read all non-overlapping matches into an array.

  i, re.I    [*all:*]{style="color: gray"} ignores case. Upper case letters match lower case letters and vice versa.

  m, re.M    [*JavaScript, PHP, Python:*]{style="color: gray"} makes the \^ and \$ match the right and left edge of newlines in addition to the beginning and end of the string.\
             [*Ruby:*]{style="color: gray"} makes the period . match newline characters.

  o          [*Ruby:*]{style="color: gray"} performs variable interpolation \#{ } only once per execution of the program.

  s, re.S    [*PHP, Python:*]{style="color: gray"} makes the period . match newline characters.

  x, re.X    [*all:*]{style="color: gray"} ignores whitespace (outside of \[\] character classes) and \#-style comments in the regex.
  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**python:**

Python modifiers are bit flags. To use more than one flag at the same
time, join them with bit or: \|

There are alternative identifiers for the modifiers:

  ------ ---------------
  re.A   re.ASCII
  re.I   re.IGNORECASE
  re.M   re.MULTILINE
  re.S   re.DOTALL
  re.X   re.VERBOSE
  ------ ---------------

[]{#subst-note}

[substitution](#subst) {#toc100}
----------------------

How to replace all occurrences of a matching pattern in a string with
the provided substitution string.

**php:**

The number of occurrences replaced can be controlled with a 4th argument
to `preg_replace`:

::: {.code}
    $s = "foo bar bar";
    preg_replace('/bar/', "baz", $s, 1);
:::

If no 4th argument is provided, all occurrences are replaced.

**python:**

The 3rd argument to `sub` controls the number of occurrences which are
replaced.

::: {.code}
    s = 'foo bar bar'
    re.compile('bar').sub('baz', s, 1)
:::

If there is no 3rd argument, all occurrences are replaced.

**ruby:**

The *gsub* operator returns a copy of the string with the substitution
made, if any. The *gsub!* performs the substitution on the original
string and returns the modified string.

The *sub* and *sub!* operators only replace the first occurrence of the
match pattern.

[]{#match-prematch-postmatch-note}

[match, prematch, postmatch](#match-prematch-postmatch) {#toc101}
-------------------------------------------------------

How to get the substring that matched the regular expression, as well as
the part of the string before and after the matching substring.

**ruby:**

The special variables `$&`, `` $` ``, and `$'` also contain the match,
prematch, and postmatch.

[]{#group-capture-note}

[group capture](#group-capture) {#toc102}
-------------------------------

How to get the substrings which matched the parenthesized parts of a
regular expression.

**ruby:**

Ruby has syntax for extracting a group from a match in a single
expression. The following evaluates to \"1999\":

::: {.code}
    "1999-07-08"[/(\d{4})-(\d{2})-(\d{2})/, 1]
:::

[]{#named-group-capture-note}

[named group capture](#named-group-capture) {#toc103}
-------------------------------------------

How to get the substrings which matched the parenthesized parts of a
regular expression and put them into a dictionary.

For reference, we call the `(?P<foo>...)` notation *Python-style* and
the `(?<foo>...)` notation *Perl-style*.

**php:**

PHP originally supported Python-style named groups since that was the
style that was added to the PCRE regex engine. Perl-style named groups
were added to PHP 5.2.

**python:**

The Python interpreter was the first to support named groups.

[]{#scan-note}

[scan](#scan) {#toc104}
-------------

How to return all non-overlapping substrings which match a regular
expression as an array.

[]{#backreference-note}

[backreference in match and substitution](#backreference) {#toc105}
---------------------------------------------------------

How to use backreferences in a regex; how to use backreferences in the
replacement string of substitution.

[]{#recursive-regex-note}

[recursive regex](#recursive-regex) {#toc106}
-----------------------------------

An examples of a recursive regex.

The example matches substrings containing balanced parens.

[]{#dates-time-note}

[Date and Time](#dates-time) {#toc107}
============================

In ISO 8601 terminology, a *date* specifies a day in the Gregorian
calendar and a *time* does not contain date information; it merely
specifies a time of day. A data type which combines both date and time
information is convenient, but ISO 8601 doesn\'t provide a name for such
an entity. PHP, Python, and C\# use the compound noun *datetime* for
combined date and time values and we adopt it here as a generic term.

An useful property of [ISO 8601 dates, times, and
datetimes](http://en.wikipedia.org/wiki/ISO_8601) is that they are
correctly ordered by a lexical sort on their string representations.
This is because they are big-endian (the year is the leftmost element)
and they used fixed-length, zero-padded fields with numerical values for
each term in the string representation.

The C standard library provides two methods for representing dates. The
first is the *Unix epoch*, which is the seconds since the beginning of
January 1, 1970 in UTC. If such a time were stored in a 32-bit signed
integer, the rollover would happen on January 18, 2038. The Unix epoch
is an example of a *serial datetime*, in which the value is stored as a
single numeric value representing the difference in time in some unit
from a specially designated datetime called the epoch.

Another serial datetime is the *Windows file time*, which is the number
of 100 nanosecond intervals since the beginning of January 1, 1601 UTC.
It was introduced when journaling was added to NTFS as part of the
Windows 2000 launch.

Some serial datetimes use days as the unit. The Excel *serial number* is
the number of days since December 31, 1899. The *Julian day number*,
used in astronomy, is the number of days since November 24, 4714 BCE in
the proleptic Gregorian calendar. Julian days start at noon GMT.

A *broken-down datetime* uses multiple numeric values to represent the
components of a calendar date and time. An example from the C standard
library is the `tm` struct, a definition of which can be found on Unix
systems in `/usr/include/time.h`:

::: {.code}
    struct tm {
            int     tm_sec;         /* seconds after the minute [0-60] */
            int     tm_min;         /* minutes after the hour [0-59] */
            int     tm_hour;        /* hours since midnight [0-23] */
            int     tm_mday;        /* day of the month [1-31] */
            int     tm_mon;         /* months since January [0-11] */
            int     tm_year;        /* years since 1900 */
            int     tm_wday;        /* days since Sunday [0-6] */
            int     tm_yday;        /* days since January 1 [0-365] */
            int     tm_isdst;       /* Daylight Savings Time flag */
            long    tm_gmtoff;      /* offset from CUT in seconds */
            char    *tm_zone;       /* timezone abbreviation */
    };
:::

The Linux man pages call the `tm` struct a \"broken-down\" date and
time, whereas the BSD man pages call it a \"broken-out\" date and time.

The first day in the Gregorian calendar was 15 October 1582. The
*proleptic Gregorian calendar* is an extension of the Gregorian calendar
to earlier dates. When such dates are used, they should be called out to
be precise. The epoch in the proleptic Gregorian calendar is the year
0001, also written 1 AD or 1 CE. The previous year is the year 0000,
also written 1 BC or 1 BCE. The year before that is the year -0001, also
written 2 BC or 2 BCE. The ISO 8601 standard recommends that years
before 0000 or after 9999 be written with a plus or minus sign prefix.

An *ordinal date* is a broken-down date consisting of a year, followed
by the day of the year. The ISO 8601 standard recommends that it be
written in `YYYY-DDD` or `YYYYDDD` format. The corresponding `strftime`
formats are `%Y-%j` and `%Y%j`.

A *week date* is a type of calendar which uses the year, week of the
year, and day of the week to refer to to dates. In the ISO 8601 week
date, the first week of the year is the week starting from Monday which
contains January 4th. An ISO 8601 week date can thus have a different
year number than the corresponding Gregorian date. The first week of the
year is numbered `01`, and the first day of the week, Monday, is
numbered `1`. Weeks are written in `YYYY-Www-D` or `YYYYWwwD` format,
where the upper case W is literal. The corresponding `strftime` literals
are `%G-W%V-%u` and `%GW%V%u`.

Common years have 365 days and leap years have 366 days. The extra day
in February 29th. Leap years are years divisible by 4 but not 100, or
years divisible by 400.

In 1967, the definition of a second was changed from 1/86,400 of a solar
day to a value expressed in terms of radiation produced by ^133^Cs.
Because the length of a solar day is irregular, leap seconds are
occasionally used to keep things in sync. This is accomplished by
occasionally adding a leap second to the end of June 30th or December
31st. The system also allows for removing the last second of June 30th
or December 31st, though as of 2014 this hasn\'t been done.

[]{#broken-down-datetime-type-note}

[broken-down datetime type](#broken-down-datetime-type) {#toc108}
-------------------------------------------------------

The data type used to hold a combined date and time.

**python:**

Python uses and exposes the `tm` struct of the C standard library.
Python has a module called `time` which is a thin wrapper to the
standard library functions which operate on this struct. Here is how get
a `tm` struct in Python:

::: {.code}
    import time

    utc = time.gmtime(time.time())
    t = time.localtime(time.time())
:::

[]{#current-datetime-note}

[current datetime](#current-datetime) {#toc109}
-------------------------------------

How to get the combined date and time for the present moment in both
local time and UTC.

[]{#current-unix-epoch-note}

[current unix epoch](#current-unix-epoch) {#toc110}
-----------------------------------------

How to get the current time as a Unix epoch timestamp.

[]{#broken-down-datetime-to-unix-epoch-note}

[broken-down datetime to unix epoch](#broken-down-datetime-to-unix-epoch) {#toc111}
-------------------------------------------------------------------------

How to convert a datetime type to the Unix epoch which is the number of
seconds since the start of January 1, 1970 UTC.

**python:**

The Python datetime object created by `now()` and `utcnow()` has no
timezone information associated with it. The `strftime()` method assumes
a receiver with no time zone information represents a local time. Thus
it is an error to call `strftime()` on the return value of `utcnow()`.

Here are two different ways to get the current Unix epoch. The second
way is faster:

::: {.code}
    import calendar
    import datetime

    int(datetime.datetime.now().strftime('%s'))
    calendar.timegm(datetime.datetime.utcnow().utctimetuple())
:::

Replacing `now()` with `utcnow()` in the first way, or `utcnow()` with
`now()` in the second way produces an incorrect value.

[]{#unix-epoch-to-broken-down-datetime-note}

[unix epoch to broken-down datetime](#unix-epoch-to-broken-down-datetime) {#toc112}
-------------------------------------------------------------------------

How to convert the Unix epoch to a broken-down datetime.

[]{#fmt-datetime-note}

[format datetime](#fmt-datetime) {#toc113}
--------------------------------

How to format a datetime as a string using using a string of format
specifiers.

The format specifiers used by the `strftime` function from the standard
C library and the Unix `date` command:

  ----------------------------------------------------------------------------------------------------------------------------------------------
                            numeric     alphanumeric   notes
  ------------------------- ----------- -------------- -----------------------------------------------------------------------------------------
  **year**                  \%Y %C%y                   \%C and %y are the first two and last two digits of a 4 digit year

  **month**                 \%m         \%B %b %h      \%m is zero padded in {01, ..., 12}\
                                                       %h is blank padded in {1, ..., 12}

  **day of month**          \%d %e                     \%d is zero padded in {01, ..., 31}\
                                                       %e is blank padded in {1, ..., 31}

  **hour**                  \%H %k      \%I%p %l%p     \%H and %k are in zero and blank padded

  **minute**                \%M                        \%M is zero padded in the range {00, ..., 59}

  **second**                \%S                        \%S is zero padded, due to leap seconds it is in the range {00, ..., 60}

  **day of year**           \%j                        \%j is zero padded in the range {000, ..., 366}

  **week date year**        \%G %g                     the ISO 8601 week date year. Used with %V and %u.

  **week of year**          \%V %U %W                  \%V is the ISO 8601 week of year. In {01, 53}. Used with %G\
                                                       %U is the week number when Sunday starts the week. In {00, 53}. Used with %Y and %C%y.\
                                                       %W is the week number when Monday starts the week. In {00, 53}. Used with %Y and %C%y.

  **day of week**           \%u %w      \%A %a         \%u is in {{1, ..., 7} starting at Monday\
                                                       %w is in {0, ..., 6} starting at Sunday

  **unix epoch**            \%s                        

  **date**                  \%D %F %x   \%v            \%D is %m/%d/%y\
                                                       %F is %Y-%m-%d\
                                                       %x locale dependent; same as %D in US

  **time**                  \%T %R %X   \%r            \%T is %H:%M:%S\
                                                       %R is %H:%M\
                                                       %X is locale dependent; same as %T in US\
                                                       %r is %I:%M:%S %p

  **date and time**                     \%c            locale dependent

  **date, time, and tmz**               \%+            locale dependent

  **time zone name**                    \%Z            the ambiguous 3 letter abbrevation; e.g. \"PST\"

  **time zone offset**      \%z                        \"-0800\" for Pacific Standard Time

  **percent sign**                      \%%            

  **newline**                           \%n            

  **tab**                               \%t            
  ----------------------------------------------------------------------------------------------------------------------------------------------

**php:**

PHP supports strftime but it also has its own time formatting system
used by `date`, `DateTime::format`, and `DateTime::createFromFormat`.
The letters used in the PHP time formatting system are [described
here](http://www.php.net/manual/en/datetime.createfromformat.php).

[]{#parse-datetime-note}

[parse datetime](#parse-datetime) {#toc114}
---------------------------------

How to parse a datetime using the format notation of the `strptime`
function from the standard C library.

[]{#parse-datetime-without-fmt-note}

[parse datetime w/o format](#parse-datetime-without-fmt) {#toc115}
--------------------------------------------------------

How to parse a date without providing a format string.

[]{#date-parts-note}

[date parts](#date-parts) {#toc116}
-------------------------

How to get the year, month, and day of month from a datetime.

[]{#time-parts-note}

[time parts](#time-parts) {#toc117}
-------------------------

How to the hour, minute, and second from a datetime.

[]{#build-datetime-note}

[build broken-down datetime](#build-datetime) {#toc118}
---------------------------------------------

How to build a broken-down datetime from the date parts and the time
parts.

[]{#datetime-subtraction-note}

[datetime subtraction](#datetime-subtraction) {#toc119}
---------------------------------------------

The data type that results when subtraction is performed on two combined
date and time values.

[]{#add-duration-note}

[add duration](#add-duration) {#toc120}
-----------------------------

How to add a duration to a datetime.

A duration can easily be added to a datetime value when the value is a
Unix epoch value.

ISO 8601 distinguishes between a time interval, which is defined by two
datetime endpoints, and a duration, which is the length of a time
interval and can be defined by a unit of time such as \'10 minutes\'. A
time interval can also be defined by date and time representing the
start of the interval and a duration.

ISO 8601 defines [notation for
durations](http://en.wikipedia.org/wiki/ISO_8601#Durations). This
notation starts with a \'P\' and uses a \'T\' to separate the day and
larger units from the hour and smaller units. Observing the location
relative to the \'T\' is important for interpreting the letter \'M\',
which is used for both months and minutes.

[]{#local-tmz-determination-note}

[local time zone determination](#local-tmz-determination) {#toc121}
---------------------------------------------------------

Do datetime values include time zone information. When a datetime value
for the local time is created, how the local time zone is determined.

On Unix systems processes determine the local time zone by inspecting
the binary file `/etc/localtime`. To examine it from the command line
use `zdump`:

::: {.code}
    $ zdump /etc/localtime
    /etc/localtime  Tue Dec 30 10:03:27 2014 PST
:::

On Windows the time zone name is stored in the registry at
`HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation\TimeZoneKeyName`.

**php:**

The default time zone can also be set in the `php.ini` file.

::: {.code}
    date.timezone = "America/Los_Angeles"
:::

Here is the list of [timezones supported by
PHP](http://php.net/timezones).

[]{#nonlocal-tmz-note}

[nonlocal time zone](#nonlocal-tmz) {#toc122}
-----------------------------------

How to convert a datetime to the equivalent datetime in an arbitrary
time zone.

[]{#tmz-info-note}

[time zone info](#tmz-info) {#toc123}
---------------------------

How to get the name of the time zone and the offset in hours from UTC.

Timezones are often identified by [three or four letter
abbreviations](http://en.wikipedia.org/wiki/List_of_time_zone_abbreviations).
Many of the abbreviations do not uniquely identify a time zone.
Furthermore many of the time zones have been altered in the past. The
[Olson database](http://en.wikipedia.org/wiki/Tz_database) (aka Tz
database) decomposes the world into zones in which the local clocks have
all been set to the same time since 1970; it gives these zones unique
names.

**ruby:**

The `Time` class has a `zone` method which returns the time zone
abbreviation for the object. There is a `tzinfo` gem which can be used
to create time zone objects using the Olson database name. This can in
turn be used to convert between UTC times and local times which are
daylight saving aware.

[]{#daylight-savings-test-note}

[daylight savings test](#daylight-savings-test) {#toc124}
-----------------------------------------------

Is a datetime in daylight savings time?

[]{#microseconds-note}

[microseconds](#microseconds) {#toc125}
-----------------------------

How to get the microseconds component of a combined date and time value.
The SI abbreviations for milliseconds and microseconds are `ms` and
`μs`, respectively. The C standard library uses the letter `u` as an
abbreviation for `micro`. Here is a struct defined in
`/usr/include/sys/time.h`:

::: {.code}
    struct timeval {
      time_t       tv_sec;   /* seconds since Jan. 1, 1970 */
      suseconds_t  tv_usec;  /* and microseconds */
    };
:::

[]{#sleep-note}

[sleep](#sleep) {#toc126}
---------------

How to put the process to sleep for a specified number of seconds. In
Python and Ruby the default version of `sleep` supports a fractional
number of seconds.

**php:**

PHP provides `usleep` which takes an argument in microseconds:

::: {.code}
    usleep(500000);
:::

[]{#timeout-note}

[timeout](#timeout) {#toc127}
-------------------

How to cause a process to timeout if it takes too long.

Techniques relying on SIGALRM only work on Unix systems.

[]{#arrays-note}

[Arrays](#arrays) {#toc128}
=================

What the languages call their basic container types:

                                javascript   php     python                  ruby
  ----------------------------- ------------ ------- ----------------------- -------------------
  [array](#array-literal)                    array   list, tuple, sequence   Array, Enumerable
  [dictionary](#dict-literal)                array   dict, mapping           Hash

**javascript:**

**php:**

PHP uses the same data structure for arrays and dictionaries.

**python:**

Python has the mutable *list* and the immutable *tuple*. Both are
*sequences*. To be a *sequence*, a class must implement
[\_\_getitem\_\_]{style="white-space: pre-wrap;"},
[\_\_setitem\_\_]{style="white-space: pre-wrap;"},
[\_\_delitem\_\_]{style="white-space: pre-wrap;"},
[\_\_len\_\_]{style="white-space: pre-wrap;"},
[\_\_contains\_\_]{style="white-space: pre-wrap;"},
[\_\_iter\_\_]{style="white-space: pre-wrap;"},
[\_\_add\_\_]{style="white-space: pre-wrap;"},
[\_\_mul\_\_]{style="white-space: pre-wrap;"},
[\_\_radd\_\_]{style="white-space: pre-wrap;"}, and
[\_\_rmul\_\_]{style="white-space: pre-wrap;"}.

**ruby:**

Ruby provides an *Array* datatype. If a class defines an *each* iterator
and a comparison operator \<=\>, then it can mix in the *Enumerable*
module.

[]{#array-literal-note}

[literal](#array-literal) {#toc129}
-------------------------

Array literal syntax.

**ruby:**

The `%w` operator splits the following string on whitespace and creates
an array of strings from the words. The character following the `%w` is
the string delimiter. If the following character is (, \[, or {, then
the character which terminates the string must be ), \], or }.

The `%W` operator is like the `%w` operator, except that double-quote
style `#{ }` expressions will be interpolated.

[]{#quote-words-note}

[quote words](#quote-words) {#toc130}
---------------------------

The quote words operator, which is a literal for arrays of strings where
each string contains a single word.

[]{#array-size-note}

[size](#array-size) {#toc131}
-------------------

How to get the number of elements in an array.

[]{#array-empty-note}

[empty test](#array-empty) {#toc132}
--------------------------

How to test whether an array is empty.

[]{#array-lookup-note}

[lookup](#array-lookup) {#toc133}
-----------------------

How to access a value in an array by index.

**python:**

A negative index refers to the *length - index* element.

::: {.code}
    >>> a = [1, 2, 3]
    >>> a[-1]
    3
:::

**ruby:**

A negative index refers to to the *length - index* element.

[]{#array-update-note}

[update](#array-update) {#toc134}
-----------------------

How to update the value at an index.

[]{#array-out-of-bounds-note}

[out-of-bounds behavior](#array-out-of-bounds) {#toc135}
----------------------------------------------

What happens when the value at an out-of-bounds index is referenced.

[]{#array-element-index-note}

[element index](#array-element-index) {#toc136}
-------------------------------------

How to get the index of an element in an array.

**php:**

Setting the 3rd argument of `array_search` to true makes the search use
`===` for an equality test. Otherwise the `==` test is performed, which
makes use of implicit type conversions.

[]{#array-slice-note}

[slice](#array-slice) {#toc137}
---------------------

How to slice a subarray from an array by specifying a start index and an
end index; how to slice a subarray from an array by specifying an offset
index and a length index.

**python:**

Slices can leave the first or last index unspecified, in which case the
first or last index of the sequence is used:

::: {.code}
    >>> a=[1, 2, 3, 4, 5]
    >>> a[:3]
    [1, 2, 3]
:::

Python has notation for taking every nth element:

::: {.code}
    >>> a=[1, 2, 3, 4, 5]
    >>> a[::2] 
    [1, 3, 5]
:::

The third argument in the colon-delimited slice argument can be
negative, which reverses the order of the result:

::: {.code}
    >>> a = [1, 2, 3, 4]
    >>> a[::-1]
    [4, 3, 2, 1]
:::

[]{#array-slice-to-end-note}

[slice to end](#array-slice-to-end) {#toc138}
-----------------------------------

How to slice to the end of an array.

The examples take all but the first element of the array.

[]{#array-back-note}

[manipulate back](#array-back) {#toc139}
------------------------------

How to add and remove elements from the back or high index end of an
array.

These operations can be used to use the array as a stack.

[]{#array-front-note}

[manipulate front](#array-front) {#toc140}
--------------------------------

How to add and remove elements from the front or low index end of an
array.

These operations can be used to use the array as a stack. They can be
used with the operations that manipulate the back of the array to use
the array as a queue.

[]{#array-concatenation-note}

[concatenate](#array-concatenation) {#toc141}
-----------------------------------

How to create an array by concatenating two arrays; how to modify an
array by concatenating another array to the end of it.

[]{#replicate-array-note}

[replicate](#replicate-array) {#toc142}
-----------------------------

How to create an array containing the same value replicated *n* times.

[]{#array-copy-note}

[copy](#array-copy) {#toc143}
-------------------

How to make an address copy, a shallow copy, and a deep copy of an
array.

After an address copy is made, modifications to the copy also modify the
original array.

After a shallow copy is made, the addition, removal, or replacement of
elements in the copy does not modify of the original array. However, if
elements in the copy are modified, those elements are also modified in
the original array.

A deep copy is a recursive copy. The original array is copied and a deep
copy is performed on all elements of the array. No change to the
contents of the copy will modify the contents of the original array.

**python:**

The slice operator can be used to make a shallow copy:

::: {.code}
    a2 = a[:]
:::

`list(v)` always returns a list, but `v[:]` returns a value of the same
as `v`. The slice operator can be used in this manner on strings and
tuples but there is little incentive to do so since both are immutable.

`copy.copy` can be used to make a shallow copy on types that don\'t
support the slice operator such as a dictionary. Like the slice operator
`copy.copy` returns a value with the same type as the argument.

[]{#array-as-func-arg-note}

[array as function argument](#array-as-func-arg) {#toc144}
------------------------------------------------

How an array is passed to a function when provided as an argument.

[]{#iterate-over-array-note}

[iterate over elements](#iterate-over-array) {#toc145}
--------------------------------------------

How to iterate over the elements of an array.

[]{#indexed-array-iteration-note}

[iterate over indices and elements](#indexed-array-iteration) {#toc146}
-------------------------------------------------------------

How to iterate over the element-index pairs.

[]{#range-iteration-note}

[iterate over range](#range-iteration) {#toc147}
--------------------------------------

Iterate over a range without instantiating it as a list.

[]{#range-array-note}

[instantiate range as array](#range-array) {#toc148}
------------------------------------------

How to convert a range to an array.

Python 3 ranges and Ruby ranges implement some of the functionality of
arrays without allocating space to hold all the elements.

**python:**

In Python 2 `range()` returns a list.

In Python 3 `range()` returns an object which implements the immutable
sequence API.

**ruby:**

The Range class includes the Enumerable module.

[]{#array-reverse-note}

[reverse](#array-reverse) {#toc149}
-------------------------

How to create a reversed copy of an array, and how to reverse an array
in place.

**python:**

`reversed` returns an iterator which can be used in a `for/in`
construct:

::: {.code}
    print("counting down:")
    for i in reversed([1, 2, 3]):
      print(i)
:::

`reversed` can be used to create a reversed list:

::: {.code}
    a = list(reversed([1, 2, 3]))
:::

[]{#array-sort-note}

[sort](#array-sort) {#toc150}
-------------------

How to create a sorted copy of an array, and how to sort an array in
place. Also, how to set the comparison function when sorting.

**php:**

`usort` sorts an array in place and accepts a comparison function as a
2nd argument:

::: {.code}
    function cmp($x, $y) {
      $lx = strtolower($x);
      $ly = strtolower($y);
      if ( $lx < $ly ) { return -1; }
      if ( $lx == $ly ) { return 0; }
      return 1;
    }

    $a = ["b", "A", "a", "B"];

    usort($a, "cmp");
:::

**python:**

In Python 2 it is possible to specify a binary comparision function when
calling `sort`:

::: {.code}
    a = [(1, 3), (2, 2), (3, 1)]

    a.sort(cmp=lambda a, b: -1 if a[1] < b[1] else 1)

    # a now contains:
    [(3, 1), (2, 2), (1, 3)]
:::

In Python 3 the `cmp` parameter was removed. One can achieve the same
effect by defining `cmp` method on the class of the list element.

[]{#array-dedupe-note}

[dedupe](#array-dedupe) {#toc151}
-----------------------

How to remove extra occurrences of elements from an array.

**python:**

Python sets support the `len`, `in`, and `for` operators. It may be more
efficient to work with the result of the set constructor directly rather
than convert it back to a list.

[]{#membership-note}

[membership](#membership) {#toc152}
-------------------------

How to test for membership in an array.

[]{#intersection-note}

[intersection](#intersection) {#toc153}
-----------------------------

How to compute an intersection.

**python:**

Python has literal notation for sets:

::: {.code}
    {1, 2, 3}
:::

Use `set` and `list` to convert lists to sets and vice versa:

::: {.code}
    a = list({1, 2, 3})
    ensemble = set([1, 2, 3])
:::

**ruby:**

The intersect operator `&` always produces an array with no duplicates.

[]{#union-note}

[union](#union) {#toc154}
---------------

**ruby:**

The union operator `|` always produces an array with no duplicates.

[]{#set-diff-note}

[relative complement, symmetric difference](#set-diff) {#toc155}
------------------------------------------------------

How to compute the relative complement of two arrays or sets; how to
compute the symmetric difference.

**ruby:**

If an element is in the right argument, then it will not be in the
return value even if it is contained in the left argument multiple
times.

[]{#map-note}

[map](#map) {#toc156}
-----------

Create an array by applying a function to each element of a source
array.

**ruby:**

The `map!` method applies the function to the elements of the array in
place.

`collect` and `collect!` are synonyms for `map` and `map!`.

[]{#filter-note}

[filter](#filter) {#toc157}
-----------------

Create an array containing the elements of a source array which match a
predicate.

**ruby:**

The in place version is `select!`.

`reject` returns the complement of `select`. `reject!` is the in place
version.

The `partition` method returns two arrays:

::: {.code}
    a = [1, 2, 3]
    lt2, ge2 = a.partition { |n| n < 2 }
:::

[]{#reduce-note}

[reduce](#reduce) {#toc158}
-----------------

Return the result of applying a binary operator to all the elements of
the array.

**python:**

`reduce` is not needed to sum a list of numbers:

::: {.code}
    sum([1, 2, 3])
:::

**ruby:**

The code for the reduction step can be provided by name. The name can be
a symbol or a string:

::: {.code}
    [1, 2, 3].inject(:+)

    [1, 2, 3].inject("+")

    [1, 2, 3].inject(0, :+)

    [1, 2, 3].inject(0, "+")
:::

[]{#universal-existential-test-note}

[universal and existential tests](#universal-existential-test) {#toc159}
--------------------------------------------------------------

How to test whether a condition holds for all members of an array; how
to test whether a condition holds for at least one member of any array.

A universal test is always true for an empty array. An existential test
is always false for an empty array.

A existential test can readily be implemented with a filter. A universal
test can also be implemented with a filter, but it is more work: one
must set the condition of the filter to the negation of the predicate
and test whether the result is empty.

[]{#shuffle-sample-note}

[shuffle and sample](#shuffle-sample) {#toc160}
-------------------------------------

How to shuffle an array. How to extract a random sample from an array.

**php:**

The `array_rand` function returns a random sample of the indices of an
array. The result can easily be converted to a random sample of array
values:

::: {.code}
    $a = [1, 2, 3, 4];
    $sample = [];
    foreach (array_rand($a, 2) as $i) { array_push($sample, $a[$i]); }
:::

[]{#flatten-note}

[flatten](#flatten) {#toc161}
-------------------

How to flatten nested arrays by one level or completely.

When nested arrays are flattened by one level, the depth of each element
which is not in the top level array is reduced by one.

Flattening nested arrays completely leaves no nested arrays. This is
equivalent to extracting the leaf nodes of a tree.

**php, python:**

To flatten by one level use reduce. Remember to handle the case where an
element is not array.

To flatten completely write a recursive function.

[]{#zip-note}

[zip](#zip) {#toc162}
-----------

How to interleave arrays. In the case of two arrays the result is an
array of pairs or an associative list.

[]{#dictionaries-note}

[Dictionaries](#dictionaries) {#toc163}
=============================

[]{#dict-literal-note}

[literal](#dict-literal) {#toc164}
------------------------

The syntax for a dictionary literal.

[]{#dict-size-note}

[size](#dict-size) {#toc165}
------------------

How to get the number of dictionary keys in a dictionary.

[]{#dict-lookup-note}

[lookup](#dict-lookup) {#toc166}
----------------------

How to lookup a dictionary value using a dictionary key.

[]{#dict-missing-key-note}

[missing key behavior](#dict-missing-key) {#toc167}
-----------------------------------------

What happens when a lookup is performed on a key that is not in a
dictionary.

**python:**

Use `dict.get()` to avoid handling `KeyError` exceptions:

::: {.code}
    d = {}
    d.get('lorem')      # returns None
    d.get('lorem', '')  # returns ''
:::

[]{#dict-key-check-note}

[is key present](#dict-key-check) {#toc168}
---------------------------------

How to check for the presence of a key in a dictionary without raising
an exception. Distinguishes from the case where the key is present but
mapped to null or a value which evaluates to false.

[]{#dict-delete-note}

[delete](#dict-delete) {#toc169}
----------------------

How to remove a key/value pair from a dictionary.

[]{#dict-assoc-array-note}

[from array of pairs, from even length array](#dict-assoc-array) {#toc170}
----------------------------------------------------------------

How to create a dictionary from an array of pairs; how to create a
dictionary from an even length array.

[]{#dict-merge-note}

[merge](#dict-merge) {#toc171}
--------------------

How to merge the values of two dictionaries.

In the examples, if the dictionaries `d1` and `d2` share keys then the
values from `d2` will be used in the merged dictionary.

[]{#dict-invert-note}

[invert](#dict-invert) {#toc172}
----------------------

How to turn a dictionary into its inverse. If a key \'foo\' is mapped to
value \'bar\' by a dictionary, then its inverse will map the key \'bar\'
to the value \'foo\'. However, if multiple keys are mapped to the same
value in the original dictionary, then some of the keys will be
discarded in the inverse.

[]{#dict-iter-note}

[iteration](#dict-iter) {#toc173}
-----------------------

How to iterate through the key/value pairs in a dictionary.

**python:**

In Python 2.7 `dict.items()` returns a list of pairs and
`dict.iteritems()` returns an iterator on the list of pairs.

In Python 3 `dict.items()` returns an iterator and `dict.iteritems()`
has been removed.

[]{#dict-key-val-note}

[keys and values as arrays](#dict-key-val) {#toc174}
------------------------------------------

How to convert the keys of a dictionary to an array; how to convert the
values of a dictionary to an array.

**python:**

In Python 3 `dict.keys()` and `dict.values()` return read-only views
into the dict. The following code illustrates the change in behavior:

::: {.code}
    d = {}
    keys = d.keys()
    d['foo'] = 'bar'

    if 'foo' in keys:
      print('running Python 3')
    else:
      print('running Python 2')
:::

[]{#dict-sort-values-note}

[sort by values](#dict-sort-values) {#toc175}
-----------------------------------

How to iterate through the key-value pairs in the order of the values.

[]{#dict-default-val-note}

[default value, computed value](#dict-default-val) {#toc176}
--------------------------------------------------

How to create a dictionary with a default value for missing keys; how to
compute and store the value on lookup.

**php:**

Extend `ArrayObject` to compute values on lookup:

::: {.code}
    class Factorial extends ArrayObject {

      public function offsetExists($i) {
        return true;
      }

      public function offsetGet($i) {
        if(!parent::offsetExists($i)) {
          if ( $i < 2 ) {
            parent::offsetSet($i, 1);
          }
          else {
            $n = $this->offsetGet($i-1);
            parent::offsetSet($i, $i*$n);
          }
        }
        return parent::offsetGet($i);
      }
    }

    $factorial = new Factorial();
:::

[]{#functions-note}

[Functions](#functions) {#toc177}
=======================

Python has both functions and methods. Ruby only has methods: functions
defined at the top level are in fact methods on a special main object.
Perl subroutines can be invoked with a function syntax or a method
syntax.

[]{#def-func-note}

[define](#def-func) {#toc178}
-------------------

How to define a function.

[]{#invoke-func-note}

[invoke](#invoke-func) {#toc179}
----------------------

How to invoke a function.

**python:**

Parens are mandatory, even for functions which take no arguments.
Omitting the parens returns the function or method as an object.
Whitespace can occur between the function name and the following left
paren.

In Python 3 print is a function instead of a keyword; parens are
mandatory around the argument.

**ruby:**

Ruby parens are optional. Leaving out the parens results in ambiguity
when function invocations are nested. The interpreter resolves the
ambiguity by assigning as many arguments as possible to the innermost
function invocation, regardless of its actual arity. It is mandatory
that the left paren not be separated from the method name by whitespace.

[]{#apply-func-note}

[apply function to array](#apply-func) {#toc180}
--------------------------------------

How to apply a function to an array.

**perl:**

Perl passes the elements of arrays as individual arguments. In the
following invocation, the function `foo()` does not know which arguments
came from which array. For that matter it does not know how many arrays
were used in the invocation:

::: {.code}
    foo(@a, @b);
:::

If the elements must be kept in their respective arrays the arrays must
be passed by reference:

::: {.code}
    sub foo {
      my @a = @{$_[0]};
      my @b = @{$_[1]};
    }

    foo(\@a, \@b);
:::

When hashes are used as arguments, each key and value becomes its own
argument.

[]{#missing-arg-note}

[missing argument behavior](#missing-arg) {#toc181}
-----------------------------------------

What happens when a function is invoked with too few arguments.

[]{#extra-arg-note}

[extra argument behavior](#extra-arg) {#toc182}
-------------------------------------

What happens when a function is invoked with too many arguments.

[]{#default-arg-note}

[default argument](#default-arg) {#toc183}
--------------------------------

How to declare a default value for an argument.

[]{#variadic-func-note}

[variadic function](#variadic-func) {#toc184}
-----------------------------------

How to write a function which accepts a variable number of argument.

**python:**

This function accepts one or more arguments. Invoking it without any
arguments raises a `TypeError`:

::: {.code}
    def poker(dealer, *players):
      ...
:::

**ruby:**

This function accepts one or more arguments. Invoking it without any
arguments raises an `ArgumentError`:

::: {.code}
    def poker(dealer, *players)
      ...
    end
:::

[]{#param-alias-note}

[parameter alias](#param-alias) {#toc185}
-------------------------------

How to make a parameter an alias of a variable in the caller.

[]{#named-param-note}

[named parameters](#named-param) {#toc186}
--------------------------------

How to write a function which uses named parameters and how to invoke
it.

**python:**

The caller can use named parameter syntax at the point of invocation
even if the function was defined using positional parameters.

The splat operator \* collects the remaining arguments into a list. In a
function invocation, the splat can be used to expand an array into
separate arguments.

The double splat operator \*\* collects named parameters into a
dictionary. In a function invocation, the double splat expands a
dictionary into named parameters.

A double splat operator can be used to force the caller to use named
parameter syntax. This method has the disadvantage that spelling errors
in the parameter name are not caught:

::: {.code}
    def fequal(x, y, **kwargs):
      eps = opts.get('eps') or 0.01
      return abs(x - y) < eps
:::

In Python 3 named parameters can be made mandatory:

::: {.code}
    def fequal(x, y, *, eps):
      return abs(x-y) < eps

    fequal(1.0, 1.001, eps=0.01)  # True

    fequal(1.0, 1.001)                 # raises TypeError
:::

**ruby:**

In Ruby 2.1 named parameters can be made mandatory:

::: {.code}
    def fequals(x, y, eps:)
      (x - y).abs < eps
    end

    # false:
    fequals(1.0, 1.001, eps: 0.1**10)
    # ArgumentError:
    fequals(1.0, 1.001)
:::

[]{#retval-note}

[return value](#retval) {#toc187}
-----------------------

How the return value of a function is determined.

[]{#multiple-retval-note}

[multiple return values](#multiple-retval) {#toc188}
------------------------------------------

How to return multiple values from a function.

[]{#anonymous-func-literal-note}

[anonymous function literal](#anonymous-func-literal) {#toc189}
-----------------------------------------------------

The syntax for an anonymous function literal; i.e. a lambda function.

**python:**

Python lambdas cannot contain newlines or semicolons, and thus are
limited to a single statement or expression. Unlike named functions, the
value of the last statement or expression is returned, and a *return* is
not necessary or permitted. Lambdas are closures and can refer to local
variables in scope, even if they are returned from that scope.

If a closure function is needed that contains more than one statement,
use a nested function:

::: {.code}
    def make_nest(x):
        b = 37
        def nest(y):
            c = x*y
            c *= b
            return c
        return nest

    n = make_nest(12*2)
    print(n(23))
:::

Python closures are read only.

A nested function can be returned and hence be invoked outside of its
containing function, but it is not visible by its name outside of its
containing function.

**ruby:**

The following lambda and Proc object behave identically:

::: {.code}
    sqr = lambda { |x| x * x }

    sqr = Proc.new {|x| x * x }
:::

With respect to control words, Proc objects behave like blocks and
lambdas like functions. In particular, when the body of a Proc object
contains a `return` or `break` statement, it acts like a `return` or
`break` in the code which invoked the Proc object. A `return` in a
lambda merely causes the lambda to exit, and a `break` inside a lambda
must be inside an appropriate control structure contained with the
lambda body.

Ruby are alternate syntax for defining lambdas and invoking them:

::: {.code}
    sqr = ->(x) {x*x}

    sqr.(2)
:::

[]{#invoke-anonymous-func-note}

[invoke anonymous function](#invoke-anonymous-func) {#toc190}
---------------------------------------------------

The syntax for invoking an anonymous function.

[]{#func-as-val-note}

[function as value](#func-as-val) {#toc191}
---------------------------------

How to store a function in a variable and pass it as an argument.

**php:**

If a variable containing a string is used like a function then PHP will
look for a function with the name in the string and attempt to invoke
it.

**python:**

Python function are stored in variables by default. As a result a
function and a variable with the same name cannot share the same scope.
This is also the reason parens are mandatory when invoking Python
functions.

[]{#private-state-func-note}

[function with private state](#private-state-func) {#toc192}
--------------------------------------------------

How to create a function with private state which persists between
function invocations.

**python:**

Here is a technique for creating private state which exploits the fact
that the expression for a default value is evaluated only once:

::: {.code}
    def counter(_state=[0]):
      _state[0] += 1
      return _state[0]

    print(counter())
:::

[]{#closure-note}

[closure](#closure) {#toc193}
-------------------

How to create a first class function with access to the local variables
of the local scope in which it was created.

**python:**

Python 2 has limited closures: access to local variables in the
containing scope is read only and the bodies of anonymous functions must
consist of a single expression.

Python 3 permits write access to local variables outside the immediate
scope when declared with `nonlocal`.

[]{#generator-note}

[generator](#generator) {#toc194}
-----------------------

How to create a function which can yield a value back to its caller and
suspend execution.

**python:**

A Python generator is a function which returns an iterator.

An iterator is an object with two methods: `iter()`, which returns the
iterator itself, and `next()`, which returns the next item or raises a
`StopIteration` exception.

Python sequences, of which lists are an example, define an `iter()` for
returned an iterator which traverses the sequence.

Python iterators can be used in *for/in* statements and list
comprehensions.

In the table below, `p` and `q` are variables for iterators.

itertools

generator

description

count(start=0, step=1)

arithmetic sequence of integers

cyle(p)

cycle over `p` endlessly

repeat(v, \[n\])

return `v` `n` times, or endlessly

chain(p, q)

`p` followed by `q`

compress(p, q)

`p` if `q`

groupby(p, func)

ifilter(pred, p)

`p` if `pred(p)`

ifilterfalse(pred, p)

`p` if not `pred(p)`

islice(p, \[start\], stop, \[step\])

imap

starmap()

tee()

takewhile()

izip()

izip\_longest()

product()

permutations()

combinations()

combinations\_with\_replacement()

**ruby:**

Ruby generators are called fibers.

[]{#decorator-note}

[decorator](#decorator) {#toc195}
-----------------------

A decorator replaces an invocation of one function with another in a way
that that is imperceptible to the client.

Normally a decorator will add a small amount of functionality to the
original function which it invokes. A decorator can modify the arguments
before passing them to the original function or modify the return value
before returning it to the client. Or it can leave the arguments and
return value unmodified but perform a side effect such as logging the
call.

[]{#invoke-op-like-func-note}

[invoke operator like function](#invoke-op-like-func) {#toc196}
-----------------------------------------------------

How to call an operator using the function invocation syntax.

This is useful when dealing with an API which accepts a function as an
argument.

**python:**

The `operator` module provides functions which perform the same
operations as the various operators. Using these functions is more
efficient than wrapping the operators in lambdas.

**ruby:**

All operators can be invoked with method invocation syntax. The binary
operator invocation syntax can be regarded as syntactic sugar.

[]{#execution-control-note}

[Execution Control](#execution-control) {#toc197}
=======================================

[]{#if-note}

[if](#if) {#toc198}
---------

The conditional branch statement.

**php:**

PHP has the following alternate syntax for `if` statements:

::: {.code}
    if ($n == 0): 
      echo "no hits\n";
    elseif ($n == 1):
      echo "one hit\n";
    else:
      echo "$n hits\n";
    endif;
:::

**ruby:**

If an `if` statement is the last statement executed in a function, the
return value is the value of the branch that executed.

Ruby `if` statements are expressions. They can be used on the right hand
side of assignments:

::: {.code}
    m = if n
      1
    else
      0
    end
:::

[]{#switch-note}

[switch](#switch) {#toc199}
-----------------

A statement which branches based on the value of an expression.

[]{#while-note}

[while](#while) {#toc200}
---------------

How to loop over a block while a condition is true.

**php:**

PHP provides a `do-while` loop. The body of such a loop is guaranteed to
execute at least once.

::: {.code}
    $i = 0;
    do {
        echo $i;
    } while ($i > 0);
:::

**ruby:**

Ruby provides a loop with no exit condition:

::: {.code}
    def yes(expletive="y")
      loop do
       puts expletive
      end
    end
:::

Ruby also provides the `until` loop.

Ruby loops can be used in expression contexts but they always evaluate
to `nil`.

[]{#for-note}

[for](#for) {#toc201}
-----------

How to write a C-style for loop.

[]{#break-note}

[break](#break) {#toc202}
---------------

A `break` statement exits a `while` or `for` loop immediately.

[]{#continue-note}

[continue](#continue) {#toc203}
---------------------

A `continue` statement skips ahead to the next iteration of a `while` or
`for` loop.

**ruby:**

There is also a `redo` statement, which restarts the current iteration
of a loop.

[]{#statement-modifiers-note}

[statement modifiers](#statement-modifiers) {#toc204}
-------------------------------------------

Clauses added to the end of a statement to control execution.

Ruby has conditional statement modifiers. Ruby also has looping
statement modifiers.

**ruby:**

Ruby has the looping statement modifiers `while` and `until`:

::: {.code}
    i = 0
    i += 1 while i < 10

    j = 10
    j -= 1 until j < 0
:::

[]{#exceptions-note}

[Exceptions](#exceptions) {#toc205}
=========================

[]{#base-exc-note}

[base exception](#base-exc) {#toc206}
---------------------------

The base exception type or class that can be used to catch all
exceptions.

[]{#predefined-exc-note}

[predefined exceptions](#predefined-exc) {#toc207}
----------------------------------------

A list of the more commonly encountered exceptions.

**python:**

Code for inspecting the descendants of a base class:

::: {.code}
    def print_class_hierarchy(cls, indent=0):
        print(' ' * indent, cls.__name__)
        for subclass in cls.__subclasses__():
            print_class_hierarchy(subclass, indent + 2)
:::

The complete Python 3.5 exception hierarchy:

::: {.code}
    BaseException
      Exception
        TypeError
        ImportError
          ZipImportError
        AssertionError
        error
        ArithmeticError
          FloatingPointError
          OverflowError
          ZeroDivisionError
        SyntaxError
          IndentationError
            TabError
        OSError
          BlockingIOError
          TimeoutError
          PermissionError
          FileExistsError
          ConnectionError
            BrokenPipeError
            ConnectionAbortedError
            ConnectionResetError
            ConnectionRefusedError
          NotADirectoryError
          UnsupportedOperation
          ChildProcessError
          IsADirectoryError
          ItimerError
          InterruptedError
          FileNotFoundError
          ProcessLookupError
        BufferError
        ReferenceError
        MemoryError
        StopIteration
        StopAsyncIteration
        Error
        SystemError
          CodecRegistryError
        ValueError
          UnicodeError
            UnicodeEncodeError
            UnicodeDecodeError
            UnicodeTranslateError
          UnsupportedOperation
        NameError
          UnboundLocalError
        AttributeError
        Warning
          DeprecationWarning
          SyntaxWarning
          FutureWarning
          RuntimeWarning
          UserWarning
          UnicodeWarning
          BytesWarning
          PendingDeprecationWarning
          ResourceWarning
          ImportWarning
        RuntimeError
          RecursionError
          NotImplementedError
          _DeadlockError
        LookupError
          IndexError
          KeyError
          CodecRegistryError
        EOFError
      GeneratorExit
      KeyboardInterrupt
      SystemExit
:::

[]{#raise-exc-note}

[raise exception](#raise-exc) {#toc208}
-----------------------------

How to raise exceptions.

**ruby:**

Ruby has a *throw* keyword in addition to *raise*. *throw* can have a
symbol as an argument, and will not convert a string to a RuntimeError
exception.

[]{#catch-all-handler-note}

[catch-all handler](#catch-all-handler) {#toc209}
---------------------------------------

How to catch exceptions.

**php:**

PHP code must specify a variable name for the caught exception.
*Exception* is the top of the exception hierarchy and will catch all
exceptions.

Internal PHP functions usually do not throw exceptions. They can be
converted to exceptions with this signal handler:

::: {.code}
    function exception_error_handler($errno, $errstr, $errfile, $errline ) {
        throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
    }
    set_error_handler("exception_error_handler");
:::

**ruby:**

A *rescue Exception* clause will catch any exception. A *rescue* clause
with no exception type specified will catch exceptions that are
subclasses of *StandardError*. Exceptions outside *StandardError* are
usually unrecoverable and hence not handled in code.

In a *rescue* clause, the *retry* keyword will cause the *begin* clause
to be re-executed.

In addition to *begin* and *rescue*, ruby has *catch*:

::: {.code}
    catch (:done) do
      loop do
        retval = work
        throw :done if retval < 10
      end
    end
:::

[]{#re-raise-exc-note}

[re-raise exception](#re-raise-exc) {#toc210}
-----------------------------------

How to re-raise an exception preserving the original stack trace.

**python:**

If the exception is assigned to a variable in the `except` clause and
the variable is used as the argument to `raise`, then a new stack trace
is created.

**ruby:**

If the exception is assigned to a variable in the `rescue` clause and
the variable is used as the argument to `raise`, then the original stack
trace is preserved.

[]{#last-exc-global-note}

[global variable for last exception](#last-exc-global) {#toc211}
------------------------------------------------------

The global variable name for the last exception raised.

[]{#def-exc-note}

[define exception](#def-exc) {#toc212}
----------------------------

How to define a new variable class.

[]{#handle-exc-note}

[handle exception](#handle-exc) {#toc213}
-------------------------------

How to catch exceptions of a specific type and assign the exception a
name.

**php:**

PHP exceptions when caught must always be assigned a variable name.

[]{#finally-block-note}

[finally block](#finally-block) {#toc214}
-------------------------------

A block of statements that is guaranteed to be executed even if an
exception is thrown or caught.

[]{#threads-note}

[Threads](#threads) {#toc215}
===================

[]{#start-thread-note}

[start thread](#start-thread) {#toc216}
-----------------------------

**ruby:**

Ruby MRI threads are operating system threads, but a global interpreter
lock prevents more than one thread from executing Ruby code at a time.

[]{#wait-on-thread-note}

[wait on thread](#wait-on-thread) {#toc217}
---------------------------------

How to make a thread wait for another thread to finish.

::: {#license-area .license-area}
[issue tracker](https://github.com/clarkgrubb/hyperpolyglot/issues) \|
content of this page licensed under [creative commons
attribution-sharealike
3.0](http://creativecommons.org/licenses/by-sa/3.0/)\
:::

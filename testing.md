<!-- TITLE: Testing -->
<!-- SUBTITLE: A quick summary of Testing -->

<div id="container-wrap-wrap">

<div id="container-wrap">

<div id="container">

<div id="header">

# [<span>Hyperpolyglot</span>](/)

</div>

<div id="content-wrap">

<div id="main-content">

<div id="page-title">

Scripting Languages I: Node.js, Python, PHP, Ruby

</div>

<div id="page-content">

<span id="top"></span>*a side-by-side reference sheet*

**sheet one:** [version](#version) | [grammar and
execution](#grammar-execution) | [variables and expressions](#var-expr)
| [arithmetic and logic](#arithmetic-logic) | [strings](#strings) |
[regexes](#regexes) | [dates and time](#dates-time) | [arrays](#arrays)
| [dictionaries](#dictionaries) | [functions](#functions) | [execution
control](#execution-control) | [exceptions](#exceptions) |
[threads](#threads)

**[sheet two](/scripting2):** [streams](/scripting2#streams) |
[asynchronous events](/scripting2#async) | [files](/scripting2#files) |
[file formats](/scripting2#file-fmt) |
[directories](/scripting2#directories) | [processes and
environment](/scripting2#processes-environment) | [option
parsing](/scripting2#option-parsing) | [libraries and
namespaces](/scripting2#libraries-namespaces) |
[objects](/scripting2#objects) | [reflection](/scripting2#reflection) |
[net and web](/scripting2#net-web) | [databases](/scripting2#databases)
| [unit tests](/scripting2#unit-tests) |
[debugging](/scripting2#debugging)

<span id="version"></span>[version](#version-note)

</div>

</div>

</div>

</div>

</div>

</div>

node.js

python

php

ruby

<span id="version-used"></span>[version used](#version-used-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*6.11*</span>

<span style="color: gray">*3.6*</span>

<span style="color: gray">*7.0*</span>

<span style="color: gray">*2.3*</span>

<span id="version"></span>[show version](#version-note)  
<span style="white-space: pre-wrap;"> </span>

$ node <span style="white-space: pre-wrap;">--</span>version

$ python -V  
$ python <span style="white-space: pre-wrap;">--</span>version

$ php <span style="white-space: pre-wrap;">--</span>version

$ ruby <span style="white-space: pre-wrap;">--</span>version

<span id="implicit-prologue"></span>[implicit
prologue](#implicit-prologue-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
npm install lodash</span>  
const \_ = require('lodash');

import os, re, sys

<span style="color: gray">\# sudo apt install php-mbstring</span>

<span style="color: gray">*none*</span>

<span id="grammar-execution"></span>[grammar and
execution](#grammar-execution-note)

node.js

python

php

ruby

<span id="interpreter"></span>[interpreter](#interpreter-note)  
<span style="white-space: pre-wrap;"> </span>

$ node foo.js

$ python foo.py

$ php -f foo.php

$ ruby foo.rb

<span id="repl"></span>[repl](#repl-note)  
<span style="white-space: pre-wrap;"> </span>

$ node

$ python

$ php -a

$ irb

<span id="cmd-line-program"></span>[command line
program](#cmd-line-program-note)

$ node -e "console.log('hi\!');"

$ python -c 'print("hi\!")'

$ php -r 'echo "hi\!\\n";'

$ ruby -e 'puts "hi\!"'

<span id="block-delimiters"></span>[block
delimiters](#block-delimiters-note)  
<span style="white-space: pre-wrap;"> </span>

{}

: <span style="color: gray">*and offside rule*</span>

{}

{}  
do end

<span id="statement-separator"></span>[statement
separator](#statement-separator-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*; or newline  
  
newline not separator inside (), \[\], {}, "", '', or after binary
operator  
  
newline sometimes not separator when following line would not parse as a
valid statement*</span>

<span style="color: gray">*newline or*</span> ;  
  
<span style="color: gray">*newlines not separators inside (), \[\], {},
triple quote literals, or after backslash:
<span style="white-space: pre-wrap;">\\</span>*</span>

;  
  
<span style="color: gray">*statements must be semicolon terminated
inside {}*</span>

<span style="color: gray">*newline or*</span> ;  
  
<span style="color: gray">*newlines not separators inside (), \[\], {},
<span style="white-space: pre-wrap;">\`\`</span>, '', "", or after
binary operator or backslash:
<span style="white-space: pre-wrap;">\\</span>*</span>

<span id="source-code-encoding"></span>[source code
encoding](#source-code-encoding-note)

<span style="color: gray">*source is always UTF-8*</span>

<span style="color: gray">*Python 3 source is UTF-8 by default; Python 2
source is US-ASCII*</span>  
  
<span style="color: gray">\# -\*- coding: us-ascii -\*-</span>

<span style="color: gray">*none*</span>

<span style="color: gray">*Ruby 2.0 source is UTF-8 by default*</span>  
  
<span style="color: gray">\# -\*- coding: utf-8 -\*-</span>

<span id="eol-comment"></span>[end-of-line comment](#eol-comment-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
comment</span>

<span style="color: gray">\# comment</span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
comment  
\# comment</span>

<span style="color: gray">\# comment</span>

<span id="multiple-line-comment"></span>[multiple line
comment](#multiple-line-comment-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">/\* line  
another line \*/</span>

<span style="color: gray">*use triple quote string literal:*</span>  
  
'''comment line  
another line'''

<span style="color: gray">/\* comment line  
another line \*/</span>

<span style="color: gray">=begin  
comment line  
another line  
\=end</span>

<span id="var-expr"></span>[variables and expressions](#var-expr-note)

node.js

python

php

ruby

<span id="local-var"></span>[local variable](#local-var-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
new in ES6:</span>  
let x = 1;  
let y = 2, z = 3;  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
older alternative to let:</span>  
var x = 1;  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
let local scope is nearest  
<span style="white-space: pre-wrap;">//</span> enclosing block; var
local scope  
<span style="white-space: pre-wrap;">//</span> is nearest function
body.  
  
<span style="white-space: pre-wrap;">//</span> var variables are visible
to all code  
<span style="white-space: pre-wrap;">//</span> in the function body;
even code  
<span style="white-space: pre-wrap;">//</span> preceding the var
statement.</span>

<span style="color: gray">\# in function body:</span>  
x = 1  
y, z = 2, 3

<span style="color: gray">\# in function body:</span>  
$x = 1;  
list($y, $z) = \[2, 3\];

x = 1  
y, z = 2, 3

<span id="file-scope-var"></span>[file scope
variable](#file-scope-var-note)

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
outside any function body:</span>  
let n = 1;  
  
incrFileVar () { n++; }

<span style="color: gray">*none*</span>

<span style="color: gray">*none*</span>

<span style="color: gray">*none*</span>

<span id="global-var"></span>[global variable](#global-var-note)

global.g = 1;  
  
incrGlobal () { global.g++; }

g = 1  
  
def incr\_global():  
<span style="white-space: pre-wrap;">  </span>global g  
<span style="white-space: pre-wrap;">  </span>g += 1

$g = 1;  
  
function incr\_global() {  
<span style="white-space: pre-wrap;">  </span>global $g;  
<span style="white-space: pre-wrap;">  </span>++$g;  
}

$g = 1  
  
def incr\_global  
<span style="white-space: pre-wrap;">  </span>$g += 1  
end

<span id="const"></span>[constant](#const-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
new in ES6</span>  
const PI = 3.14;

<span style="color: gray">\# uppercase identifiers  
\# constant by convention</span>  
PI = 3.14

define("PI", 3.14);  
  
const PI = 3.14;

<span style="color: gray">\# warning if capitalized  
\# identifier is reassigned</span>  
PI = 3.14

<span id="assignment"></span>[assignment](#assignment-note)  
<span style="white-space: pre-wrap;"> </span>

v = 1;

<span style="color: gray">\# assignments can be chained  
\# but otherwise don't return values:</span>  
v = 1

$v = 1;

v = 1

<span id="parallel-assignment"></span>[parallel
assignment](#parallel-assignment-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
new in ES6:</span>  
let \[x, y, z\] = \[1, 2, 3\];

x, y, z = 1, 2, 3  
  
<span style="color: gray">\# raises ValueError:</span>  
x, y = 1, 2, 3  
  
<span style="color: gray">\# raises ValueError:</span>  
x, y, z = 1, 2

list($x, $y, $z) = \[1 ,2, 3\];  
  
<span style="color: gray">\# 3 is discarded:</span>  
list($x, $y) = \[1, 2, 3\];  
  
<span style="color: gray">\# $z set to NULL:</span>  
list($x, $y, $z) = \[1, 2\];

x, y, z = 1, 2, 3  
  
<span style="color: gray">\# 3 is discarded:</span>  
x, y = 1, 2, 3  
  
<span style="color: gray">\# z set to nil:</span>  
x, y, z = 1, 2

<span id="swap"></span>[swap](#swap-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
new in ES6:</span>  
\[x, y\] = \[y, x\];

x, y = y, x

list($x, $y) = \[$y, $x\];

x, y = y, x

<span id="compound-assignment"></span>[compound
assignment](#compound-assignment-note)  
<span style="color: gray">*arithmetic, string, logical, bit*</span>

\+= -= \*= /= <span style="color: gray">*none*</span> %=  
\+=  
<span style="color: gray">*none*</span>  
<span style="white-space: pre-wrap;">\<\<= \>\>= </span>&= |= ^=

<span style="color: gray">\# do not return values:</span>  
\+= -= \*= /= <span style="white-space: pre-wrap;">//</span>= %=
<span style="white-space: pre-wrap;">\*\*</span>=  
\+= \*=  
&= <span style="white-space: pre-wrap;">|</span>= ^=  
<span style="white-space: pre-wrap;">\<\<= \>\>= </span>&= |= ^=

\+= -= \*= <span style="color: gray">*none*</span> /= %=
<span style="white-space: pre-wrap;">\*\*</span>=  
.= <span style="color: gray">*none*</span>  
&= |= <span style="color: gray">*none*</span>  
<span style="white-space: pre-wrap;">\<\<= \>\>= </span>&= |= ^=

\+= -= \*= /= <span style="color: gray">*none*</span> %=
<span style="white-space: pre-wrap;">\*\*</span>=  
\+= \*=  
&&= <span style="white-space: pre-wrap;">||</span>= ^=  
<span style="white-space: pre-wrap;">\<\<= \>\>= </span>&= |= ^=

<span id="incr-decr"></span>[increment and decrement](#incr-decr-note)  
<span style="white-space: pre-wrap;"> </span>

let x = 1;  
let y = ++x;  
let z = <span style="white-space: pre-wrap;">--</span>y;

<span style="color: gray">*none*</span>

$x = 1;  
$y = ++$x;  
$z = <span style="white-space: pre-wrap;">--</span>$y;

x = 1  
<span style="color: gray">\# x and y not mutated:</span>  
y = x.succ  
z = y.pred

<span id="null"></span>[null](#null-note)  
<span style="white-space: pre-wrap;"> </span>

null

None

NULL <span style="color: gray">\# case insensitive</span>

nil

<span id="null-test"></span>[null test](#null-test-note)  
<span style="white-space: pre-wrap;"> </span>

v === null

v is None

is\_null($v)  
\! isset($v)

v == nil  
v.nil?

<span id="undef-var"></span>[undefined variable](#undef-var-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*Evaluates as*</span> undefined  
  
<span style="color: gray">*Use the triple equality*</span> ===
<span style="color: gray">*operator to test for this value.*</span>

<span style="color: gray">*raises*</span> NameError

<span style="color: gray">*Evaluates as*</span> NULL

<span style="color: gray">*raises*</span> NameError

<span id="conditional-expr"></span>[conditional
expression](#conditional-expr-note)  
<span style="white-space: pre-wrap;"> </span>

x \> 0 ? x : -x

x if x \> 0 else -x

$x \> 0 ? $x : -$x

x \> 0 ? x : -x

<span id="arithmetic-logic"></span>[arithmetic and
logic](#arithmetic-logic-note)

node.js

python

php

ruby

<span id="true-false"></span>[true and false](#true-false-note)  
<span style="white-space: pre-wrap;"> </span>

true false

True False

TRUE FALSE <span style="color: gray">\# case insensitive</span>

true false

<span id="falsehoods"></span>[falsehoods](#falsehoods-note)  
<span style="white-space: pre-wrap;"> </span>

false null undefined '' 0 NaN

False None 0 0.0 '' \[\] {}

FALSE NULL 0 0.0 "" "0" \[\]

false nil

<span id="logical-op"></span>[logical operators](#logical-op-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="white-space: pre-wrap;">&& ||</span> \!

and or not

&& <span style="white-space: pre-wrap;">||</span> \!  
<span style="color: gray">*lower precedence:*</span>  
and or xor

&& <span style="white-space: pre-wrap;">||</span> \!  
<span style="color: gray">*lower precedence:*</span>  
and or not

<span id="relational-op"></span>[relational
operators](#relational-op-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="white-space: pre-wrap;">===</span> \!== \< \> \>= \<=  
  
<span style="color: gray">*perform type coercion:*</span>  
<span style="white-space: pre-wrap;">==</span> \!=

<span style="color: gray">*relational operators are chainable:*</span>  
\== \!= \> \< \>= \<=

\== \!= <span style="color: gray">*or*</span> \<\> \> \< \>= \<=  
<span style="color: gray">*no conversion:*</span> === \!==

\== \!= \> \< \>= \<=

<span id="min-max"></span>[min and max](#min-max-note)  
<span style="white-space: pre-wrap;"> </span>

Math.min(1, 2, 3)  
Math.max(1, 2, 3)  
  
Math.min.apply(Math, \[1, 2, 3\])  
Math.max.apply(Math, \[1, 2, 3\])

min(1, 2, 3)  
max(1, 2, 3)  
  
min(\[1, 2, 3\])  
max(\[1, 2, 3\])

min(1, 2, 3)  
max(1, 2, 3)  
$a = \[1, 2, 3\]  
min($a)  
max($a)

\[1, 2, 3\].min  
\[1, 2, 3\].max

<span id="arith-op"></span>[arithmetic operators](#arith-op-note)  
<span style="color: gray">*addition, subtraction, multiplication, float
division, quotient, remainder*</span>

\+ - \* / <span style="color: gray">*none*</span> %

\+ - \* / // %  
  
<span style="color: gray">*In Python 2, / performs integer
division.*</span>

\+ - \* / <span style="color: gray">*none*</span> %

\+ - \* x.fdiv(y) / %

<span id="int-div"></span>[integer division](#int-div-note)  
<span style="white-space: pre-wrap;"> </span>

Math.floor(22 / 7)

22 // 7

(int)(22 / 7)

22 / 7

<span id="divmod"></span>[divmod](#divmod-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*none*</span>

q, r = divmod(22, 7)

<span style="color: gray">*none*</span>

q, r = 22.divmod(7)

<span id="int-div-zero"></span>[integer division by
zero](#int-div-zero-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*Returns Infinity, NaN, or -Infinity depending
upon sign of dividend.  
  
There are literals for Infinity and NaN.*</span>

<span style="color: gray">*raises* ZeroDivisionError</span>

<span style="color: gray">*returns* FALSE *with warning*</span>

<span style="color: gray">*raises* ZeroDivisionError</span>

<span id="float-div"></span>[float division](#float-div-note)  
<span style="white-space: pre-wrap;"> </span>

22 / 7

22 / 7  
  
<span style="color: gray">\# Python 2:</span>  
float(22) / 7

22 / 7

22.to\_f / 7  
  
22.fdiv(7)

<span id="float-div-zero"></span>[float division by
zero](#float-div-zero-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*same behavior as for integers*</span>

<span style="color: gray">*raises* ZeroDivisionError</span>

<span style="color: gray">*returns* FALSE *with warning*</span>

<span style="color: gray">*returns* -Infinity, NaN, *or* Infinity</span>

<span id="power"></span>[power](#power-note)  
<span style="white-space: pre-wrap;"> </span>

Math.pow(2, 32)

2 <span style="white-space: pre-wrap;">\*\*</span> 32

pow(2, 32)

2 <span style="white-space: pre-wrap;">\*\*</span> 32

<span id="sqrt"></span>[sqrt](#sqrt-note)

Math.sqrt(2)

import math  
  
math.sqrt(2)

sqrt(2)

include Math  
  
sqrt(2)

<span id="sqrt-negative-one"></span>[sqrt -1](#sqrt-negative-one-note)  
<span style="white-space: pre-wrap;"> </span>

NaN

<span style="color: gray">\# raises ValueError:</span>  
import math  
math.sqrt(-1)  
  
<span style="color: gray">\# returns complex float:</span>  
import cmath  
cmath.sqrt(-1)

NaN

<span style="color: gray">Math.sqrt(-1) raises Math::DomainError unless
require 'complex' is in effect.</span>  
  
<span style="color: gray">(-1) \*\* 0.5 is (0+1.0i)</span>

<span id="transcendental-func"></span>[transcendental
functions](#transcendental-func-note)  
<span style="white-space: pre-wrap;"> </span>

Math.exp Math.log Math.sin Math.cos Math.tan Math.asin Math.acos
Math.atan Math.atan2

from math import exp, log, \\  
sin, cos, tan, asin, acos, atan, atan2

exp log sin cos tan asin acos atan atan2

include Math  
  
exp log sin cos tan asin acos atan atan2

<span id="transcendental-const"></span>[transcendental
constants](#transcendental-const-note)  
<span style="color: gray">*π and e*</span>

Math.PI  
Math.E

import math  
  
math.pi math.e

M\_PI M\_E

include Math  
  
PI E

<span id="float-truncation"></span>[float
truncation](#float-truncation-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*none*</span>  
Math.round(3.1)  
Math.floor(3.1)  
Math.ceil(3.1)

import math  
  
int(x)  
int(round(x))  
math.ceil(x)  
math.floor(x)

(int)$x  
round($x)  
ceil($x)  
floor($x)

x.to\_i  
x.round  
x.ceil  
x.floor

<span id="abs-val"></span>[absolute value](#abs-val-note)  
<span style="white-space: pre-wrap;"> </span>

Math.abs(-3)

abs(x)

abs($x)

x.abs

<span id="int-overflow"></span>[integer overflow](#int-overflow-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*all numbers are floats*</span>

<span style="color: gray">*becomes arbitrary length integer of type*
long</span>

<span style="color: gray">*converted to float*</span>

<span style="color: gray">*becomes arbitrary length integer of type*
Bignum</span>

<span id="float-overflow"></span>[float
overflow](#float-overflow-note)  
<span style="white-space: pre-wrap;"> </span>

Infinity

<span style="color: gray">*raises* OverflowError</span>

INF

Infinity

<span id="rational-construction"></span>[rational
construction](#rational-construction-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*none*</span>

from fractions import Fraction  
  
x = Fraction(22, 7)

<span style="color: gray">*none*</span>

22 / 7r  
22r / 7

<span id="rational-decomposition"></span>[rational
decomposition](#rational-decomposition-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*none*</span>

x.numerator  
x.denominator

<span style="color: gray">*none*</span>

(22 / 7r).numerator  
(22 / 7r).denominator

<span id="complex-construction"></span>[complex
construction](#complex-construction-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*none*</span>

z = 1 + 1.414j

<span style="color: gray">*none*</span>

z = 1 + 1.414i

<span id="complex-decomposition"></span>[complex
decomposition](#complex-decomposition-note)  
<span style="color: gray">*real and imaginary component, argument,
absolute value, conjugate*</span>

<span style="color: gray">*none*</span>

import cmath  
  
z.real  
z.imag  
cmath.phase(z)  
abs(z)  
z.conjugate()

<span style="color: gray">*none*</span>

(1 + 3i).real  
(1 + 3i).imag  
(1 + 3i).arg  
(1 + 3i).abs  
(1 + 3i).conj

<span id="random-num"></span>[random number](#random-num-note)  
<span style="color: gray">*uniform integer, uniform float, normal
float*</span>

Math.floor(Math.random() \* 100)  
Math.random()  
<span style="color: gray">*none*</span>

import random  
  
random.randint(0, 99)  
random.random()  
random.gauss(0, 1)

rand(0,99)  
lcg\_value()  
<span style="color: gray">*none*</span>

rand(100)  
rand  
<span style="color: gray">*none*</span>

<span id="random-seed"></span>[random seed](#random-seed-note)  
<span style="color: gray">*set, get, restore*</span>

<span style="color: gray">*none*</span>

import random  
  
random.seed(17)  
seed = random.getstate()  
random.setstate(seed)

srand(17);  
  
<span style="color: gray">*none*</span>

srand(17)  
  
seed = srand  
srand(seed)

<span id="bit-op"></span>[bit operators](#bit-op-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="white-space: pre-wrap;">\<\< \>\> & | ^ \~</span>

<span style="white-space: pre-wrap;">\<\< \>\> & | ^ \~</span>

<span style="white-space: pre-wrap;">\<\< \>\> & | ^ \~</span>

<span style="white-space: pre-wrap;">\<\< \>\> & | ^ \~</span>

<span id="binary-octal-hex-literals"></span>[binary, octal, and hex
literals](#binary-octal-hex-literals-note)

<span style="color: gray">*none*</span>  
052
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
deprecated</span>  
0x2a

0b101010  
0o52<span style="white-space: pre-wrap;">  </span><span style="color: gray"><span style="white-space: pre-wrap;">\#</span>
also 052 in Python 2</span>  
0x2a

0b101010  
052  
0x2a

0b101010  
052  
0x2a

<span id="radix"></span>[radix](#radix-note)  
<span style="color: gray">*convert integer to and from string with
radix*</span>

(42).toString(7)  
parseInt('60', 7)

<span style="color: gray">*none*</span>  
int('60', 7)

base\_convert("42", 10, 7);  
base\_convert("60", 7, 10);

42.to\_s(7)  
"60".to\_i(7)

<span id="strings"></span>[strings](#strings-note)

node.js

python

php

ruby

<span id="str-type"></span>[string type](#str-type-note)  
<span style="white-space: pre-wrap;"> </span>

String

str  
  
<span style="color: gray">\# Python 2:</span>  
unicode

<span style="color: gray">\# array of bytes:</span>  
string

String

<span id="str-literal"></span>[string literal](#str-literal-note)  
<span style="white-space: pre-wrap;"> </span>

'don\\'t say "no"'  
"don't say \\"no\\""

'don\\'t say "no"'  
"don't say \\"no\\""  
"don't " 'say "no"'  
  
<span style="color: gray">\# Python 2 (and Python 3):</span>  
u'lorem'  
u"ipsum"

"don't say \\"no\\""  
'don\\'t say "no"'

"don't say \\"no\\""  
'don\\'t say "no"'  
"don't " 'say "no"'

<span id="newline-in-str-literal"></span>[newline in
literal](#newline-in-str-literal-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
backquote literals only:</span>  
<span style="white-space: pre-wrap;">\`</span>first line  
second line<span style="white-space: pre-wrap;">\`</span>  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
Backslashes can be used to break  
<span style="white-space: pre-wrap;">//</span> long strings.</span>

<span style="color: gray">\# triple quote literals only:</span>  
'''first line  
second line'''  
  
"""first line  
second line"""

'first line  
second line'  
  
"first line  
second line"

'first line  
second line'  
  
"first line  
second line"

<span id="str-literal-esc"></span>[literal
escapes](#str-literal-esc-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*single and double quotes:*</span>  
\\b \\f \\n \\r \\t \\v \\x<span style="color: gray">*hh*</span> \\" \\'
\\\\  
\\u<span style="color: gray">*hhhh*</span>
\\u{<span style="color: gray">*hhhhh*</span>}

\\<span style="color: gray">*newline*</span> \\\\ \\' \\" \\a \\b \\f
\\n \\r \\t \\v \\<span style="color: gray">*ooo*</span>
\\x<span style="color: gray">*hh*</span>
\\u<span style="color: gray">*hhhh*</span>
\\U<span style="color: gray">*hhhhhhhh*</span>  
  
<span style="color: gray">*In Python 2,* \\u *and* \\U *only available
in string literals with* u *prefix*</span>

<span style="color: gray">*double quoted:*</span>  
\\f \\n \\r \\t \\v \\x<span style="color: gray">*hh*</span> \\$ \\"
\\\\ \\<span style="color: gray">*ooo*</span>  
  
<span style="color: gray">*single quoted:*</span>  
\\' \\\\

<span style="color: gray">*double quoted:*</span>  
\\a \\b \\c<span style="color: gray">*x*</span> \\e \\f \\n \\r \\s \\t
\\v \\x<span style="color: gray">*hh*</span>
\\<span style="color: gray">*ooo*</span>
\\u<span style="color: gray">*hhhh*</span>
\\u{<span style="color: gray">*hhhhh*</span>}  
  
<span style="color: gray">*single quoted:*</span>  
\\' \\\\

<span id="here-doc"></span>[here document](#here-doc-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*none*</span>

<span style="color: gray">*none*</span>

$word = "amet";  
  
$s = <span style="white-space: pre-wrap;">\<\<\<</span>EOF  
lorem ipsum  
dolor sit $word  
EOF;

word = "amet"  
  
s = <span style="white-space: pre-wrap;">\<\<</span>EOF  
lorem ipsum  
dolor sit \#{word}  
EOF

<span id="var-interpolation"></span>[variable
interpolation](#var-interpolation-note)  
<span style="white-space: pre-wrap;"> </span>

let count = 3;  
let item = 'ball';  
let s = <span style="white-space: pre-wrap;">\`</span>${count}
${item}s<span style="white-space: pre-wrap;">\`</span>;

count = 3  
item = 'ball'  
print('{count}
{item}s'.format(  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">\*\*</span>locals()))  
  
<span style="color: gray">\# Python 3.6:</span>  
print(f'{count} {item}s')

$count = 3;  
$item = "ball";  
echo "$count ${item}s\\n";

count = 3  
item = "ball"  
puts "\#{count} \#{item}s"

<span id="expr-interpolation"></span>[expression
interpolation](#expr-interpolation-note)

<span style="white-space: pre-wrap;">\`</span>1 + 1 = ${1 +
1}<span style="white-space: pre-wrap;">\`</span>

'1 + 1 = {}'.format(1 + 1)  
  
<span style="color: gray">\# Python 3.6:</span>  
f'1 + 1 = {1 + 1}'

<span style="color: gray">*none*</span>

"1 + 1 = \#{1 + 1}"

<span id="format-str"></span>[format string](#format-str-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
None; use string concatenation.  
<span style="white-space: pre-wrap;">//</span> Evaluates to
"12.35":</span>  
12.3456.toFixed(2)

'lorem %s %d %f' % ('ipsum', 13, 3.7)  
  
fmt = 'lorem {0} {1} {2}'  
fmt.format('ipsum', 13, 3.7)

$fmt = "lorem %s %d %f";  
sprintf($fmt, "ipsum", 13, 3.7);

"lorem %s %d %f" % \["ipsum", 13, 3.7\]

<span id="mutable-str"></span>[are strings mutable?](#mutable-str-note)

<span style="color: gray">*no*</span>

<span style="color: gray">*no*</span>

$s = "bar";  
$s2 = $s;  
<span style="color: gray">\# sets s to "baz"; s2 is unchanged:</span>  
$s\[2\] = "z";

s = "bar"  
s2 = s  
<span style="color: gray">\# sets s and s2 to "baz":</span>  
s\[2\] = "z"

<span id="copy-str"></span>[copy string](#copy-str-note)

<span style="color: gray">*none*</span>

<span style="color: gray">*none*</span>

$s2 = $s;

s = "bar"  
s2 = s.clone  
<span style="color: gray">\# s2 is not altered:</span>  
s\[2\] = "z"

<span id="str-concat"></span>[concatenate](#str-concat-note)  
<span style="white-space: pre-wrap;"> </span>

s = 'Hello, ' + 'World\!';

s = 'Hello, '  
s2 = s + 'World\!'  
  
<span style="color: gray">\# juxtaposition can be used to  
\# concatenate literals:</span>  
s2 = 'Hello, ' "World\!"

$s = "Hello, ";  
$s2 = $s . "World\!";

s = "Hello, "  
s2 = s + "World\!"  
  
<span style="color: gray">\# juxtaposition can be used to  
\# concatenate literals:</span>  
s2 = "Hello, " 'World\!'

<span id="str-replicate"></span>[replicate](#str-replicate-note)  
<span style="white-space: pre-wrap;"> </span>

let hbar = \_.repeat('-', 80);

hbar = '-' \* 80

$hbar = str\_repeat("-", 80);

hbar = "-" \* 80

<span id="translate-case"></span>[translate
case](#translate-case-note)  
<span style="color: gray">*to upper, to lower*</span>

'lorem'.toUpperCase()  
'LOREM'.toLowerCase()

'lorem'.upper()  
'LOREM'.lower()

mb\_strtoupper("lorem")  
mb\_strtolower("LOREM")  
<span style="color: gray">\# strtoupper/strtolower are ASCII only</span>

"lorem".upcase  
"LOREM".downcase

<span id="capitalize"></span>[capitalize](#capitalize-note)  
<span style="color: gray">*string, words*</span>

\_.capitalize('lorem');  
<span style="color: gray">*none*</span>

import string  
  
'lorem'.capitalize()  
string.capwords('lorem ipsum')

<span style="color: gray">\# ASCII only:</span>  
ucfirst(strtolower("lorem"))  
ucwords(strtolower("lorem ipsum"))  
<span style="color: gray">\# Unicode title case:</span>  
mb\_convert\_case("lorem ipsum", MB\_CASE\_TITLE)

"lorem".capitalize  
<span style="color: gray">*none*</span>

<span id="trim"></span>[trim](#trim-note)  
<span style="color: gray">*both sides, left, right*</span>

' lorem '.trim()  
' lorem'.trimLeft()  
'lorem '.trimRight()

' lorem '.strip()  
' lorem'.lstrip()  
'lorem '.rstrip()

trim(" lorem ")  
ltrim(" lorem")  
rtrim("lorem ")

" lorem ".strip  
" lorem".lstrip  
"lorem ".rstrip

<span id="pad"></span>[pad](#pad-note)  
<span style="color: gray">*on right, on left, centered*</span>

\_.padStart('lorem', 10)  
\_.padEnd('lorem', 10)  
\_.pad('lorem', 10)

'lorem'.ljust(10)  
'lorem'.rjust(10)  
'lorem'.center(10)

$s = "lorem";  
$delta = strlen($s) - mb\_strlen($s);  
str\_pad($s, 10 + $delta)  
str\_pad("$s, 10 + $delta, " ", STR\_PAD\_LEFT)  
str\_pad($s, 10 + $delta, " ", STR\_PAD\_BOTH)

"lorem".ljust(10)  
"lorem".rjust(10)  
"lorem".center(10)

<span id="num-to-str"></span>[number to string](#num-to-str-note)  
<span style="white-space: pre-wrap;"> </span>

'value: ' + 8

'value: ' + str(8)

"value: " . 8

"value: " + 8.to\_s

<span id="fmt-float"></span>[format float](#fmt-float-note)

'' + Math.round(Math.PI \* 100) / 100

import math  
  
'%.2f' % math.pi  
'{:.3}'.format(math.pi)  
<span style="color: gray">\# Python 3.6:</span>  
f'{math.pi:.{3}}'

number\_format(M\_PI, 2)

include Math  
  
'%.2f' % PI  
"\#{PI.round(2)}"

<span id="str-to-num"></span>[string to number](#str-to-num-note)  
<span style="white-space: pre-wrap;"> </span>

7 + parseInt('12;, 10)  
73.9 + parseFloat('.037')  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
12:</span>  
parseInt('12A')  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
NaN:</span>  
parseInt('A')

7 + int('12')  
73.9 + float('.037')  
  
<span style="color: gray">\# raises ValueError:</span>  
int('12A')  
<span style="color: gray">\# raises ValueError:</span>  
int('A')

7 + "12"  
73.9 + ".037"  
  
<span style="color: gray">\# 12:</span>  
0 + "12A"  
<span style="color: gray">\# 0:</span>  
0 + "A"

7 + "12".to\_i  
73.9 + ".037".to\_f  
  
<span style="color: gray">\# 12:</span>  
"12A".to\_i  
<span style="color: gray">\# 0:</span>  
"A".to\_i

<span id="str-join"></span>[string join](#str-join-note)  
<span style="white-space: pre-wrap;"> </span>

\['do', 're', 'mi'\].join(' ')

' '.join(\['do', 're', 'mi', 'fa'\])  
  
<span style="color: gray">\# raises TypeError:</span>  
' '.join(\[1, 2, 3\])

$a = \["do", "re", "mi", "fa"\];  
implode(" ", $a)

%w(do re mi fa).join(' ')  
  
<span style="color: gray">\# implicitly converted to strings:</span>  
\[1, 2, 3\].join(' ')

<span id="split"></span>[split](#split-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
\[ 'do', 're', '', 'mi', '' \]:</span>  
'do re<span style="white-space: pre-wrap;">  </span>mi '.split(' ')  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
\[ 'do', 're', 'mi', '' \]:</span>  
'do re<span style="white-space: pre-wrap;">  </span>mi '.split(/\\s+/)

<span style="color: gray">\# \['do', 're', '', 'mi', ''\]:</span>  
'do re<span style="white-space: pre-wrap;">  </span>mi '.split(' ')  
  
<span style="color: gray">\# \['do', 're', 'mi'\]:</span>  
'do re<span style="white-space: pre-wrap;">  </span>mi '.split()

<span style="color: gray">\# \[ "do", "re", "", "mi", "" \]:</span>  
explode(" ", "do re<span style="white-space: pre-wrap;">  </span>mi ")  
  
<span style="color: gray">\# \[ "do", "re", "mi", "" \]:</span>  
preg\_split('/\\s+/', "do
re<span style="white-space: pre-wrap;">  </span>mi ")

<span style="color: gray">\# \["do", "re", "", "mi"\]:</span>  
"do re<span style="white-space: pre-wrap;">  </span>mi ".split(/ /)  
  
<span style="color: gray">\# \["do", "re", "mi"\]:</span>  
"do re<span style="white-space: pre-wrap;">  </span>mi ".split

<span id="split-in-two"></span>[split in two](#split-in-two-note)  
<span style="white-space: pre-wrap;"> </span>

'do re mi fa'.split(/\\s+/, 2)

'do re mi fa'.split(None, 1)

preg\_split('/\\s+/', "do re mi fa", 2)

"do re mi fa".split(/\\s+/, 2)

<span id="split-keep-delimiters"></span>[split and keep
delimiters](#split-keep-delimiters-note)

<span style="color: gray">*none*</span>

re.split('(\\s+)', 'do re mi fa')

preg\_split('/(\\s+)/', "do re mi fa",  
<span style="white-space: pre-wrap;">  </span>NULL,
PREG\_SPLIT\_DELIM\_CAPTURE)

"do re mi fa".split(/(\\s+)/)

<span id="prefix-suffix-test"></span>[prefix and suffix
test](#prefix-suffix-test-note)

'foobar'.startsWith('foo')  
'foobar'.endsWith('bar')

'foobar'.startswith('foo')  
'foobar'.endswith('bar')

'foobar'.start\_with?('foo')  
'foobar'.end\_with?('bar')

<span id="str-len"></span>[length](#str-len-note)  
<span style="white-space: pre-wrap;"> </span>

'lorem'.length

len('lorem')

mb\_strlen("lorem")  
<span style="color: gray">\# strlen() counts bytes</span>

"lorem".length  
"lorem".size

<span id="index-substr"></span>[index of
substring](#index-substr-note)  
<span style="color: gray">*first, last*</span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
returns -1 if not found:</span>  
'lorem ipsum'.indexOf('ipsum')

<span style="color: gray">\# raises ValueError if not found:</span>  
'do re re'.index('re')  
'do re re'.rindex('re')  
  
<span style="color: gray">\# returns -1 if not found:</span>  
'do re re'.find('re')  
'do re re'.rfind('re')

<span style="color: gray">\# returns FALSE if not found:</span>  
mb\_strpos("do re re", "re")  
mb\_strrpos("do re re", "re")

<span style="color: gray">\# returns nil if not found:</span>  
"do re re".index("re")  
"do re re".rindex("re")

<span id="extract-substr"></span>[extract
substring](#extract-substr-note)  
<span style="color: gray">*by start and length, by start and end, by
successive starts*</span>

'lorem ipsum'.substr(6, 5)  
'lorem ipsum'.substring(6, 11)

<span style="color: gray">*none*</span>  
<span style="color: gray">*none*</span>  
'lorem ipsum'\[6:11\]

mb\_substr("lorem ipsum", 6, 5)  
<span style="color: gray">*none*</span>  
<span style="color: gray">*none*</span>

"lorem ipsum"\[6, 5\]  
"lorem ipsum"\[6<span style="white-space: pre-wrap;">..</span>10\]  
"lorem ipsum"\[6<span style="white-space: pre-wrap;">...</span>11\]

<span id="bytes-type"></span>[byte array type](#bytes-type-note)

Buffer

bytes  
  
<span style="color: gray">\# In Python 2, str also byte array
type</span>

string

Array <span style="color: gray">*of*</span> Fixnum

<span id="bytes-to-str"></span>[byte array to
string](#bytes-to-str-note)

let a = Buffer.from(\[0xce, 0xbb\]);  
let s = a.toString('utf-8');

s = b'\\xce\\xbb'.decode('utf-8')

<span style="color: gray">*strings are byte arrays*</span>

a = "\\u03bb".bytes  
s = a.pack("C\*").force\_encoding('utf-8')

<span id="str-to-bytes"></span>[string to byte
array](#str-to-bytes-note)

a = Buffer.from('\\u03bb')

a = '\\u03bb'.encode('utf-8')  
  
<span style="color: gray">\# Python 2:</span>  
a = u'\\u03bb'.encode('utf-8')

<span style="color: gray">*strings are byte arrays*</span>

a = "\\u03bb".bytes

<span id="lookup-char"></span>[character lookup](#lookup-char-note)

'lorem ipsum'\[6\]

'lorem ipsum'\[6\]

mb\_substr("lorem ipsum", 6, 1)  
<span style="color: gray">\# byte lookup:</span>  
"lorem ipsum"\[6\]

"lorem ipsum"\[6\]

<span id="chr-ord"></span>[chr and ord](#chr-ord-note)  
<span style="white-space: pre-wrap;"> </span>

String.fromCharCode(65)  
'A'.charCodeAt(0)

chr(65)  
ord('A')

<span style="color: gray">\# ASCII only:</span>  
chr(65)  
ord("A")

65.chr('UTF-8')  
"A".ord

<span id="str-to-char-array"></span>[to array of
characters](#str-to-char-array-note)  
<span style="white-space: pre-wrap;"> </span>

'abcd'.split('')

list('abcd')

str\_split("abcd")

"abcd".split("")

<span id="translate-char"></span>[translate
characters](#translate-char-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*none*</span>

from string import ascii\_lowercase  
  
ins = ascii\_lowercase  
outs = ins\[13:\] + ins\[:13\]  
table = str.maketrans(ins, outs)  
'hello'.translate(table)

$ins = implode(range("a", "z"));  
$outs = substr($ins, 13, 13) .  
<span style="white-space: pre-wrap;">  </span>substr($ins, 0, 13);  
strtr("hello", $ins, $outs)

"hello".tr("a-z", "n-za-m")

<span id="delete-char"></span>[delete characters](#delete-char-note)

<span style="color: gray">*none*</span>

table = {ord(ch): None for ch in "aeiou"}  
"disemvowel me".translate(table)

$vowels = str\_split("aeiou");  
$s = "disemvowel me";  
$s = str\_replace($vowels, "", $s);

"disemvowel me".delete("aeiou")

<span id="squeeze-char"></span>[squeeze characters](#squeeze-char-note)

<span style="color: gray">*none*</span>

re.sub('(\\s)+',
r'\\1',  
<span style="white-space: pre-wrap;">  </span>'too<span style="white-space: pre-wrap;">   </span>much<span style="white-space: pre-wrap;">   </span>space')

$s =
"too<span style="white-space: pre-wrap;">   </span>much<span style="white-space: pre-wrap;">   </span>space";  
$s = = preg\_replace('/(\\s)+/', '\\1',
$s);

"too<span style="white-space: pre-wrap;">   </span>much<span style="white-space: pre-wrap;">   </span>space".squeeze("
")

<span id="regexes"></span>[regular expressions](#regexes-note)

node.js

python

php

ruby

<span id="regex-literal"></span>[literal, custom delimited
literal](#regex-literal-note)

/lorem|ipsum/

re.compile(r'lorem|ipsum')  
<span style="color: gray">*none*</span>

'/lorem|ipsum/'  
'(/etc/hosts)'

/lorem|ipsum/  
%r(/etc/hosts)  
<span style="color: gray">\# double quoted string escapes  
\# and \#{} substitution can be used</span>

<span id="ascii-char-class-abbrev"></span>[ascii character class
abbreviations](#ascii-char-class-abbrev-note)

.<span style="white-space: pre-wrap;">   </span>\[^\\n\]  
\\d<span style="white-space: pre-wrap;">  </span>\[0-9\]  
\\D<span style="white-space: pre-wrap;">  </span>\[^0-9\]  
\\s<span style="white-space: pre-wrap;">  </span>\[ \\t\\r\\n\\f\]  
\\S<span style="white-space: pre-wrap;">  </span>\[^
\\t\\r\\n\\f\]  
\\w<span style="white-space: pre-wrap;">  </span>\[A-Za-z0-9\_\]  
\\W<span style="white-space: pre-wrap;">  </span>\[^A-Za-z0-9\_\]

.<span style="white-space: pre-wrap;">   </span>\[^\\n\]<span style="white-space: pre-wrap;">  </span><span style="color: gray">*with*
re.S *modifier matches all chars*</span>  
\\d<span style="white-space: pre-wrap;">  </span>\[0-9\]  
\\D<span style="white-space: pre-wrap;">  </span>\[^0-9\]  
\\s<span style="white-space: pre-wrap;">  </span>\[ \\t\\r\\n\\f\]  
\\S<span style="white-space: pre-wrap;">  </span>\[^ \\t\\r\\n\\f\]  
\\w<span style="white-space: pre-wrap;">  </span>\[A-Za-z0-9\_\]  
\\W<span style="white-space: pre-wrap;">  </span>\[^A-Za-z0-9\_\]  
  
<span style="color: gray">*In Python 3, the above definitions are used
when* re.A *is in effect.*</span>

.<span style="white-space: pre-wrap;">   </span>\[^\\n\]  
\\d<span style="white-space: pre-wrap;">  </span>\[0-9\]  
\\D<span style="white-space: pre-wrap;">  </span>\[^0-9\]  
\\h<span style="white-space: pre-wrap;">  </span>\[ \\t\]  
\\H<span style="white-space: pre-wrap;">  </span>\[^ \\t\]  
\\s<span style="white-space: pre-wrap;">  </span>\[ \\t\\r\\n\\f\]  
\\S<span style="white-space: pre-wrap;">  </span>\[^
\\t\\r\\n\\f\]  
\\w<span style="white-space: pre-wrap;">  </span>\[A-Za-z0-9\_\]  
\\W<span style="white-space: pre-wrap;">  </span>\[^A-Za-z0-9\_\]

.<span style="white-space: pre-wrap;">   </span>\[^\\n\]<span style="white-space: pre-wrap;">  </span><span style="color: gray">*with*
m *modifier matches all chars*</span>  
\\d<span style="white-space: pre-wrap;">  </span>\[0-9\]  
\\D<span style="white-space: pre-wrap;">  </span>\[^0-9\]  
\\h<span style="white-space: pre-wrap;">  </span>\[0-9a-fA-F\]  
\\H<span style="white-space: pre-wrap;">  </span>\[^0-9a-fA-F\]  
\\s<span style="white-space: pre-wrap;">  </span>\[ \\t\\r\\n\\f\]  
\\S<span style="white-space: pre-wrap;">  </span>\[^ \\t\\r\\n\\f\]  
\\w<span style="white-space: pre-wrap;">  </span>\[A-Za-z0-9\_\]  
\\W<span style="white-space: pre-wrap;">  </span>\[^A-Za-z0-9\_\]

<span id="unicode-char-class-abbrev"></span>[unicode character class
abbreviations](#unicode-char-class-abbrev-note)

<span style="color: gray">*none*</span>

.<span style="white-space: pre-wrap;">   </span>\[^\\n\]<span style="white-space: pre-wrap;">  </span><span style="color: gray">*with*
re.S *modifier matches all
chars*</span>  
\\d<span style="white-space: pre-wrap;">  </span>\[<span style="color: gray">*Nd*</span>\]<span style="white-space: pre-wrap;">  </span><span style="color: gray">Nd:
*Number, decimal
digit*</span>  
\\D<span style="white-space: pre-wrap;">  </span>\[^<span style="color: gray">*Nd*</span>\]  
\\s<span style="white-space: pre-wrap;">  </span>\[<span style="color: gray">*Z*</span>\\t\\n\\r\\f\\v\\x1c\\x1d\\x1e\\x1f\\x85\]  
\\S<span style="white-space: pre-wrap;">  </span>\[^<span style="color: gray">*Z*</span>\\t\\n\\r\\f\\v\\x1c\\x1d\\x1e\\x1f\\x85\]  
\\w
\[<span style="color: gray">*LN*</span>\_\]<span style="white-space: pre-wrap;">  </span><span style="color: gray">L:
*Letter*; N: *Number*</span>  
\\W \[<span style="color: gray">^*LN*</span>\_\]  
  
<span style="color: gray">*In Python 2, the above definitions are used
when* re.U *is in effect.*</span>

<span style="color: gray">*POSIX character classes such as*
\[\[:alpha:\]\] *are available, but they match sets of ASCII characters.
General category values (e.g.* \\p{L}, \\p{Lu}*) can be used. Morever,
they can be used inside character classes (.e.g.*
\[\\p{L}\\p{N}\]*).*</span>

.  
\\p{Digit}  
\\p{^Digit}  
\\p{Space}  
\\p{^Space}  
\\p{Word}  
\\p{^Word}  
  
<span style="color: gray">*POSIX character classes (e.g.*
<span style="white-space: pre-wrap;">\[\[:alpha:\]\]</span>*), general
category values (e.g.* \\p{L}, \\p{Lu}*), and script names (e.g.*
\\p{Greek}) *also
supported.*</span>

<span id="regex-anchors"></span>[anchors](#regex-anchors-note)  
<span style="white-space: pre-wrap;"> </span>

^<span style="white-space: pre-wrap;">   </span><span style="color: gray">*start
of string or line with* m
*modifier*</span>  
$<span style="white-space: pre-wrap;">   </span><span style="color: gray">*end
of string or line with* m
*modifier*</span>  
\\b<span style="white-space: pre-wrap;">  </span><span style="color: gray">*word
boundary:* \\w\\W *or*
\\W\\w</span>  
\\B<span style="white-space: pre-wrap;">  </span><span style="color: gray">*non
word
boundary*</span>

^<span style="white-space: pre-wrap;">   </span><span style="color: gray">*start
of string or line with*
re.M</span>  
$<span style="white-space: pre-wrap;">   </span><span style="color: gray">*end
of string or line with*
re.M</span>  
\\A<span style="white-space: pre-wrap;">  </span><span style="color: gray">*start
of
string*</span>  
\\b<span style="white-space: pre-wrap;">  </span><span style="color: gray">*word
boundary:* \\w\\W *or*
\\W\\w</span>  
\\B<span style="white-space: pre-wrap;">  </span><span style="color: gray">*non
word
boundary*</span>  
\\Z<span style="white-space: pre-wrap;">  </span><span style="color: gray">*end
of
string*</span>

^<span style="white-space: pre-wrap;">   </span><span style="color: gray">*start
of string or line with* m
*modifier*</span>  
$<span style="white-space: pre-wrap;">   </span><span style="color: gray">*end
of string or line with* m
*modifier*</span>  
\\A<span style="white-space: pre-wrap;">  </span><span style="color: gray">*start
of
string*</span>  
\\b<span style="white-space: pre-wrap;">  </span><span style="color: gray">*word
boundary:* \\w\\W *or*
\\W\\w</span>  
\\B<span style="white-space: pre-wrap;">  </span><span style="color: gray">*non
word
boundary*</span>  
\\z<span style="white-space: pre-wrap;">  </span><span style="color: gray">*end
of
string*</span>  
\\Z<span style="white-space: pre-wrap;">  </span><span style="color: gray">*end
of string, excluding final
newline*</span>

^<span style="white-space: pre-wrap;">   </span><span style="color: gray">*start
of
line*</span>  
$<span style="white-space: pre-wrap;">   </span><span style="color: gray">*end
of
line*</span>  
\\A<span style="white-space: pre-wrap;">  </span><span style="color: gray">*start
of
string*</span>  
\\b<span style="white-space: pre-wrap;">  </span><span style="color: gray">*unicode-aware
word
boundary*</span>  
\\B<span style="white-space: pre-wrap;">  </span><span style="color: gray">*unicode-aware
non word
boundary*</span>  
\\z<span style="white-space: pre-wrap;">  </span><span style="color: gray">*end
of
string*</span>  
\\Z<span style="white-space: pre-wrap;">  </span><span style="color: gray">*end
of string, excluding final newline*</span>

<span id="regex-test"></span>[match test](#regex-test-note)  
<span style="white-space: pre-wrap;"> </span>

if (s.match(/1999/)) {  
<span style="white-space: pre-wrap;">  </span>console.log('party\!');  
}

if re.search('1999', s):  
<span style="white-space: pre-wrap;">  </span>print('party\!')

if (preg\_match('/1999/', $s)) {  
<span style="white-space: pre-wrap;">  </span>echo "party\!\\n";  
}

if /1999/.match(s)  
<span style="white-space: pre-wrap;">  </span>puts "party\!"  
end

<span id="case-insensitive-regex"></span>[case insensitive match
test](#case-insensitive-regex-note)  
<span style="white-space: pre-wrap;"> </span>

'Lorem'.match(/lorem/i)

re.search('lorem', 'Lorem', re.I)

preg\_match('/lorem/i',
"Lorem")

/lorem/i.match("Lorem")

<span id="regex-modifiers"></span>[modifiers](#regex-modifiers-note)  
<span style="white-space: pre-wrap;"> </span>

g<span style="white-space: pre-wrap;">  </span><span style="color: gray">*used
for global substitution and
scanning*</span>  
i<span style="white-space: pre-wrap;">  </span><span style="color: gray">*make
case
insensitive*</span>  
m<span style="white-space: pre-wrap;">  </span><span style="color: gray">*change
meaning of* ^ *and*
$</span>  
u<span style="white-space: pre-wrap;">  </span><span style="color: gray">\\u{}
*syntax and astral character
support*</span>  
y<span style="white-space: pre-wrap;">  </span><span style="color: gray">*used
to scan in
loop*</span>

re.A<span style="white-space: pre-wrap;">  </span><span style="color: gray">*change
meaning of* \\b \\B \\d \\D \\s \\S \\w
\\W</span>  
re.I<span style="white-space: pre-wrap;">  </span><span style="color: gray">*make
case
insensitive*</span>  
re.M<span style="white-space: pre-wrap;">  </span><span style="color: gray">*change
meaning of* ^ *and*
$</span>  
re.S<span style="white-space: pre-wrap;">  </span><span style="color: gray">*change
meaning of*
.</span>  
re.X<span style="white-space: pre-wrap;">  </span><span style="color: gray">*ignore
whitespace outside char
class*</span>

i<span style="white-space: pre-wrap;">  </span><span style="color: gray">*make
case
insensitive*</span>  
m<span style="white-space: pre-wrap;">  </span><span style="color: gray">*change
meaning of* ^ *and*
$</span>  
s<span style="white-space: pre-wrap;">  </span><span style="color: gray">*change
meaning of*
.</span>  
x<span style="white-space: pre-wrap;">  </span><span style="color: gray">*ignore
whitespace outside char
class*</span>

i<span style="white-space: pre-wrap;">  </span><span style="color: gray">*make
case
insensitive*</span>  
o<span style="white-space: pre-wrap;">  </span><span style="color: gray">*interpolate
\#{} in literal
once*</span>  
m<span style="white-space: pre-wrap;">  </span><span style="color: gray">*change
meaning of*
.</span>  
x<span style="white-space: pre-wrap;">  </span><span style="color: gray">*ignore
whitespace outside char class*</span>

<span id="subst"></span>[substitution](#subst-note)  
<span style="white-space: pre-wrap;"> </span>

s = 'do re mi mi mi';  
s.replace(/mi/g, 'ma');

s = 'do re mi mi mi'  
s = re.compile('mi').sub('ma', s)

$s = "do re mi mi mi";  
$s = preg\_replace('/mi/', "ma", $s);

s = "do re mi mi mi"  
s.gsub\!(/mi/, "ma")

<span id="match-prematch-postmatch"></span>[match, prematch,
postmatch](#match-prematch-postmatch-note)  
<span style="white-space: pre-wrap;"> </span>

m = /\\d{4}/.exec(s);  
if (m) {  
<span style="white-space: pre-wrap;">  </span>match =
m\[0\];  
<span style="white-space: pre-wrap;">  </span><span style="color: gray"><span style="white-space: pre-wrap;">//</span>
no prematch or postmatch</span>  
}

m = re.search('\\d{4}', s)  
if m:  
<span style="white-space: pre-wrap;">  </span>match = m.group()  
<span style="white-space: pre-wrap;">  </span>prematch =
s\[0:m.start(0)\]  
<span style="white-space: pre-wrap;">  </span>postmatch =
s\[m.end(0):len(s)\]

<span style="color: gray">*none*</span>

m = /\\d{4}/.match(s)  
if m  
<span style="white-space: pre-wrap;">  </span>match = m\[0\]  
<span style="white-space: pre-wrap;">  </span>prematch = m.pre\_match  
<span style="white-space: pre-wrap;">  </span>postmatch =
m.post\_match  
end

<span id="group-capture"></span>[group capture](#group-capture-note)  
<span style="white-space: pre-wrap;"> </span>

rx = /^(\\d{4})-(\\d{2})-(\\d{2})$/;  
m = rx.exec('2009-06-03');  
yr = m\[1\];  
mo = m\[2\];  
dy = m\[3\];

rx = '(\\d{4})-(\\d{2})-(\\d{2})'  
m = re.search(rx, '2010-06-03')  
yr, mo, dy = m.groups()

$s = "2010-06-03";  
$rx = '/(\\d{4})-(\\d{2})-(\\d{2})/';  
preg\_match($rx, $s, $m);  
list($\_, $yr, $mo, $dy) = $m;

rx = /(\\d{4})-(\\d{2})-(\\d{2})/  
m = rx.match("2010-06-03")  
yr, mo, dy = m\[1..3\]

<span id="named-group-capture"></span>[named group
capture](#named-group-capture-note)

<span style="color: gray">*none*</span>

rx = '^(?P\<file\>.+)\\.(?P\<suffix\>.+)$'  
m = re.search(rx, 'foo.txt')  
  
m.groupdict()\['file'\]  
m.groupdict()\['suffix'\]

$s = "foo.txt";  
$rx = '/^(?P\<file\>.+)\\.(?P\<suffix\>.+)$/';  
preg\_match($rx, $s, $m);  
  
$m\["file"\]  
$m\["suffix"\]

rx = /^(?\<file\>.+)\\.(?\<suffix\>.+)$/  
m = rx.match('foo.txt')  
  
m\["file"\]  
m\["suffix"\]

<span id="scan"></span>[scan](#scan-note)  
<span style="white-space: pre-wrap;"> </span>

let a = 'dolor sit amet'.match(/\\w+/g);

s = 'dolor sit amet'  
a = re.findall('\\w+', s)

$s = "dolor sit amet";  
preg\_match\_all('/\\w+/', $s, $m);  
$a = $m\[0\];

a = "dolor sit amet".scan(/\\w+/)

<span id="backreference"></span>[backreference in match and
substitution](#backreference-note)

/(\\w+) \\1/.exec('do do')  
  
'do re'.replace(/(\\w+) (\\w+)/, '$2 $1')

<span style="color: gray">*none*</span>  
  
rx = re.compile('(\\w+) (\\w+)')  
rx.sub(r'\\2 \\1', 'do re')

preg\_match('/(\\w+) \\1/', "do do")  
  
$s = "do re";  
$rx = '/(\\w+) (\\w+)/';  
$s = preg\_replace($rx, '\\2 \\1', $s);

/(\\w+) \\1/.match("do do")  
  
"do re".sub(/(\\w+) (\\w+)/, '\\2 \\1')

<span id="recursive-regex"></span>[recursive
regex](#recursive-regex-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*none*</span>

<span style="color: gray">*none*</span>

'/\\((\[^()\]\*|($R))\\)/'

/(?\<foo\>\\((\[^()\]\*|\\g\<foo\>)\*\\))/

<span id="dates-time"></span>[dates and time](#dates-time-note)

node.js

python

php

ruby

<span id="broken-down-datetime-type"></span>[broken-down datetime
type](#broken-down-datetime-type-note)  
<span style="white-space: pre-wrap;"> </span>

Date

datetime.datetime

DateTime

Time

<span id="current-datetime"></span>[current
datetime](#current-datetime-note)

let t = new Date();

import datetime  
  
t = datetime.datetime.now()  
utc = datetime.datetime.utcnow()

$t = new DateTime("now");  
$utc\_tmz = new DateTimeZone("UTC");  
$utc = new DateTime("now", $utc\_tmz);

t = Time.now  
utc = Time.now.utc

<span id="current-unix-epoch"></span>[current unix
epoch](#current-unix-epoch-note)

(new Date()).getTime() / 1000

import datetime  
  
t = datetime.datetime.now()  
epoch = int(t.strftime("%s"))

$epoch = time();

epoch = Time.now.to\_i

<span id="broken-down-datetime-to-unix-epoch"></span>[broken-down
datetime to unix epoch](#broken-down-datetime-to-unix-epoch-note)

Math.round(t.getTime() / 1000)

from datetime import datetime as dt  
  
epoch = int(t.strftime("%s"))

$epoch = $t-\>getTimestamp();

epoch = t.to\_i

<span id="unix-epoch-to-broken-down-datetime"></span>[unix epoch to
broken-down datetime](#unix-epoch-to-broken-down-datetime-note)

let epoch = 1315716177;  
let t2 = new Date(epoch \* 1000);

t = dt.fromtimestamp(1304442000)

$t2 = new DateTime();  
$t2-\>setTimestamp(1304442000);

t = Time.at(1304442000)

<span id="fmt-datetime"></span>[format datetime](#fmt-datetime-note)

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
npm install moment</span>  
let moment = require('moment');  
  
let t = moment(new Date());  
let fmt = 'YYYY-MM-DD HH:mm:ss';  
console.log(t.format(fmt));

t.strftime('%Y-%m-%d %H:%M:%S')

strftime("%Y-%m-%d %H:%M:%S", $epoch);  
date("Y-m-d H:i:s", $epoch);  
$t-\>format("Y-m-d H:i:s");

t.strftime("%Y-%m-%d %H:%M:%S")

<span id="parse-datetime"></span>[parse datetime](#parse-datetime-note)

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
npm install moment</span>  
let moment = require('moment');  
  
let fmt = 'YYYY-MM-DD HH:mm:ss';  
let s = '2011-05-03 10:00:00';  
let t = moment(s, fmt);

from datetime import datetime  
  
s = '2011-05-03 10:00:00'  
fmt = '%Y-%m-%d %H:%M:%S'  
t = datetime.strptime(s, fmt)

$fmt = "Y-m-d H:i:s";  
$s = "2011-05-03 10:00:00";  
$t = DateTime::createFromFormat($fmt,  
<span style="white-space: pre-wrap;">  </span>$s);

require 'date'  
  
s = "2011-05-03 10:00:00"  
fmt = "%Y-%m-%d %H:%M:%S"  
t = DateTime.strptime(s, fmt).to\_time

<span id="parse-datetime-without-fmt"></span>[parse datetime w/o
format](#parse-datetime-without-fmt-note)

let t = new Date('July 7, 1999');

<span style="color: gray">\# pip install python-dateutil</span>  
import dateutil.parser  
  
s = 'July 7, 1999'  
t = dateutil.parser.parse(s)

$epoch = strtotime("July 7, 1999");

require 'date'  
  
s = "July 7, 1999"  
t = Date.parse(s).to\_time

<span id="date-parts"></span>[date parts](#date-parts-note)

t.getFullYear()  
t.getMonth() + 1  
t.getDate()
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
getDay() is day of week</span>

t.year  
t.month  
t.day

(int)$t-\>format("Y")  
(int)$t-\>format("m")  
(int)$t-\>format("d")

t.year  
t.month  
t.day

<span id="time-parts"></span>[time parts](#time-parts-note)

t.getHours()  
t.getMinutes()  
t.getSeconds()

t.hour  
t.minute  
t.second

(int)$t-\>format("H")  
(int)$t-\>format("i")  
(int)$t-\>format("s")

t.hour  
t.min  
t.sec

<span id="build-datetime"></span>[build broken-down
datetime](#build-datetime-note)

let yr = 1999;  
let mo = 9;  
let dy = 10;  
let hr = 23;  
let mi = 30;  
let ss = 0;  
let t = new Date(yr, mo - 1, dy,  
<span style="white-space: pre-wrap;">  </span>hr, mi, ss);

import datetime  
  
yr = 1999  
mo = 9  
dy = 10  
hr = 23  
mi = 30  
ss = 0  
t = datetime.datetime(yr, mo, dy, hr, mi, ss)

yr = 1999  
mo = 9  
dy = 10  
hr = 23  
mi = 30  
ss = 0  
t = Time.new(yr, mo, dy, hr, mi, ss)

<span id="datetime-subtraction"></span>[datetime
subtraction](#datetime-subtraction-note)

<span style="color: gray">number *containing time difference in
milliseconds*</span>

<span style="color: gray">datetime.timedelta *object*</span>  
  
<span style="color: gray">*use* total\_seconds() *method to convert to
float representing difference in seconds*</span>

<span style="color: gray">\# DateInterval object if diff method
used:</span>  
$fmt = "Y-m-d H:i:s";  
$s = "2011-05-03 10:00:00";  
$then = DateTime::createFromFormat($fmt, $s);  
$now = new DateTime("now");  
$interval = $now-\>diff($then);

<span style="color: gray">Float *containing time difference in
seconds*</span>

<span id="add-duration"></span>[add duration](#add-duration-note)

let t1 = new Date();  
let delta = (10 \* 60 + 3) \* 1000;  
let t2 = new Date(t1.getTime() + delta);

import datetime  
  
delta = datetime.timedelta(  
<span style="white-space: pre-wrap;">  </span>minutes=10,  
<span style="white-space: pre-wrap;">  </span>seconds=3)  
t = datetime.datetime.now() + delta

$now = new DateTime("now");  
$now-\>add(new DateInterval("PT10M3S");

require 'date/delta'  
  
s = "10 min, 3 s"  
delta = Date::Delta.parse(s).in\_secs  
t = Time.now + delta

<span id="local-tmz-determination"></span>[local time zone
determination](#local-tmz-determination-note)

<span style="color: gray">TZ environment variable or host time
zone</span>

<span style="color: gray">*a* datetime *object has no time zone
information unless a* tzinfo *object is provided when it is
created*</span>

<span style="color: gray">\# DateTime objects can be instantiated  
\# without specifying the time zone  
\# if a default is set:</span>  
$s = "America/Los\_Angeles";  
date\_default\_timezone\_set($s);

<span style="color: gray">*if no time zone is specified the local time
zone is used*</span>

<span id="nonlocal-tmz"></span>[nonlocal time zone](#nonlocal-tmz-note)

<span style="color: gray">\# pip install pytz</span>  
import pytz  
import datetime  
  
tmz = pytz.timezone('Asia/Tokyo')  
utc = datetime.datetime.utcnow()  
utc\_dt =
datetime.datetime(  
<span style="white-space: pre-wrap;">  </span>\*utc.timetuple()\[0:6\],  
<span style="white-space: pre-wrap;">  </span>tzinfo=pytz.utc)  
jp\_dt = utc\_dt.astimezone(tmz)

<span style="color: gray">\# gem install tzinfo</span>  
require 'tzinfo'  
  
tmz = TZInfo::Timezone.get("Asia/Tokyo")  
jp\_time = tmz.utc\_to\_local(Time.now.utc)

<span id="tmz-info"></span>[time zone info](#tmz-info-note)  
  
<span style="color: gray">*name and UTC offset*</span>

import time  
  
tm = time.localtime()  
<span style="white-space: pre-wrap;">  </span>  
time.tzname\[tm.tm\_isdst\]  
(time.timezone / -3600) + tm.tm\_isdst

$tmz = date\_timezone\_get($t);  
  
timezone\_name\_get($tmz);  
date\_offset\_get($t) / 3600;

t.zone  
t.utc\_offset / 3600

<span id="daylight-savings-test"></span>[daylight savings
test](#daylight-savings-test-note)

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
npm install moment</span>  
let moment = require('moment');  
  
moment(new Date()).isDST()

import time  
  
tm = time.localtime()  
<span style="white-space: pre-wrap;">  </span>  
tm.tm\_isdst

$t-\>format("I");

t.dst?

<span id="microseconds"></span>[microseconds](#microseconds-note)

t.getMilliseconds() \* 1000  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
\[sec, nanosec\] since system boot:</span>  
process.hrtime()

t.microsecond

list($frac, $sec) = explode(" ", microtime());  
$usec = $frac \* 1000 \* 1000;

t.usec

<span id="arrays"></span>[arrays](#arrays-note)

node.js

python

php

ruby

<span id="array-literal"></span>[literal](#array-literal-note)  
<span style="white-space: pre-wrap;"> </span>

a = \[1, 2, 3, 4\]

a = \[1, 2, 3, 4\]

$a = \[1, 2, 3, 4\];  
  
<span style="color: gray">\# older syntax:</span>  
$a = array(1, 2, 3, 4);

a = \[1, 2, 3, 4\]  
  
<span style="color: gray">\# a = \['do', 're', 'mi'\]</span>  
a = %w(do re mi)

<span id="array-size"></span>[size](#array-size-note)  
<span style="white-space: pre-wrap;"> </span>

a.length

len(a)

count($a)

a.size  
a.length

<span id="array-empty"></span>[empty test](#array-empty-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
TypeError if a is null or undefined:</span>  
a.length === 0

<span style="color: gray">\# None tests as empty:</span>  
not a

<span style="color: gray">\# NULL tests as empty:</span>  
\!$a

<span style="color: gray">\# NoMethodError if a is nil:</span>  
a.empty?

<span id="array-lookup"></span>[lookup](#array-lookup-note)  
<span style="white-space: pre-wrap;"> </span>

a\[0\]

a\[0\]  
  
<span style="color: gray">\# returns last element:</span>  
a\[-1\]

$a\[0\]  
  
<span style="color: gray">\# PHP uses the same type for arrays and  
\# dictionaries; indices can be negative  
\# integers or strings</span>

a\[0\]  
  
<span style="color: gray">\# returns last element:</span>  
a\[-1\]

<span id="array-update"></span>[update](#array-update-note)  
<span style="white-space: pre-wrap;"> </span>

a\[0\] = 'lorem'

a\[0\] = 'lorem'

$a\[0\] = "lorem";

a\[0\] = "lorem"

<span id="array-out-of-bounds"></span>[out-of-bounds
behavior](#array-out-of-bounds-note)

<span style="color: gray">*returns* undefined</span>

a = \[\]  
<span style="color: gray">\# raises IndexError:</span>  
a\[10\]  
<span style="color: gray">\# raises IndexError:</span>  
a\[10\] = 'lorem'

$a = \[\];  
<span style="color: gray">\# evaluates as NULL:</span>  
$a\[10\];  
<span style="color: gray">\# increases array size to one:</span>  
$a\[10\] = "lorem";

a = \[\]  
<span style="color: gray">\# evaluates as nil:</span>  
a\[10\]  
<span style="color: gray">\# increases array size to 11:</span>  
a\[10\] = "lorem"

<span id="array-element-index"></span>[element
index](#array-element-index-note)  
  
<span style="color: gray">*first and last occurrence*</span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
return -1 if not found:</span>  
\[6, 7, 7, 8\].indexOf(7)  
\[6, 7, 7, 8\].lastIndexOf(7)

a = \['x', 'y', 'y', 'z'\]  
  
<span style="color: gray">\# raises ValueError if not found:</span>  
a.index('y')  
<span style="color: gray">*none*</span>

$a = \["x", "y", "y", "z"\];  
  
<span style="color: gray">\# returns FALSE if not found:</span>  
$i = array\_search("y", $a, TRUE);  
<span style="color: gray">*none*</span>

a = %w(x y y z)  
  
<span style="color: gray">\# return nil if not found:</span>  
a.index('y')  
a.rindex('y')

<span id="array-slice"></span>[slice](#array-slice-note)  
<span style="color: gray">*by endpoints, by length*</span>  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
select 3rd and 4th elements:</span>  
\['a', 'b', 'c', 'd'\].slice(2, 4)  
<span style="color: gray">*none*</span>

<span style="color: gray">\# select 3rd and 4th elements:</span>  
a\[2:4\]  
a\[<span style="white-space: pre-wrap;">2:2</span> + 2\]

<span style="color: gray">\# select 3rd and 4th elements:</span>  
<span style="color: gray">*none*</span>  
array\_slice($a, 2, 2)

<span style="color: gray">\# select 3rd and 4th elements:</span>  
a\[2..3\]  
a\[2, 2\]

<span id="array-slice-to-end"></span>[slice to
end](#array-slice-to-end-note)  
<span style="white-space: pre-wrap;"> </span>

\['a', 'b', 'c', 'd'\].slice(1)

a\[1:\]

array\_slice($a, 1)

a\[1..-1\]

<span id="array-back"></span>[manipulate back](#array-back-note)  
<span style="white-space: pre-wrap;"> </span>

a = \[6, 7, 8\];  
a.push(9);  
i = a.pop();

a = \[6, 7, 8\]  
a.append(9)  
a.pop()

$a = \[6, 7, 8\];  
array\_push($a, 9);  
$a\[\] = 9; <span style="color: gray">\# same as array\_push</span>  
array\_pop($a);

a = \[6, 7, 8\]  
a.push(9)  
a <span style="white-space: pre-wrap;">\<\<</span> 9
<span style="color: gray">\# same as push</span>  
a.pop

<span id="array-front"></span>[manipulate front](#array-front-note)  
<span style="white-space: pre-wrap;"> </span>

a = \[6, 7, 8\];  
a.unshift(5);  
i = a.shift();

a = \[6, 7, 8\]  
a.insert(0, 5)  
a.pop(0)

$a = \[6, 7, 8\];  
array\_unshift($a, 5);  
array\_shift($a);

a = \[6, 7,
8\]  
a.unshift(5)  
a.shift

<span id="array-concatenation"></span>[concatenate](#array-concatenation-note)

a = \[1, 2, 3\].concat(\[4, 5, 6\]);

a = \[1, 2, 3\]  
a2 = a + \[4, 5, 6\]  
a.extend(\[4, 5, 6\])

$a = \[1, 2, 3\];  
$a2 = array\_merge($a, \[4, 5, 6\]);  
$a = array\_merge($a, \[4, 5, 6\]);

a = \[1, 2, 3\]  
a2 = a + \[4, 5, 6\]  
a.concat(\[4, 5, 6\])

<span id="replicate-array"></span>[replicate](#replicate-array-note)

Array(10).fill(null)

a = \[None\] \* 10  
a = \[None for i in range(0, 10)\]

$a = array\_fill(0, 10, NULL);

a = \[nil\] \* 10  
a = Array.new(10, nil)

<span id="array-copy"></span>[copy](#array-copy-note)  
<span style="color: gray">*address copy, shallow copy, deep copy*</span>

a = \[1, 2, \[3, 4\]\];  
a2 = a;  
a3 = a.slice(0);  
a4 = JSON.parse(JSON.stringify(a));

import copy  
  
a = \[1,2,\[3,4\]\]  
a2 = a  
a3 = list(a)  
a4 = copy.deepcopy(a)

$a = \[1, 2, \[3, 4\]\];  
$a2 =& $a;  
<span style="color: gray">*none*</span>  
$a4 = $a;

a = \[1,2,\[3,4\]\]  
a2 = a  
a3 = a.dup  
a4 = Marshal.load(Marshal.dump(a))

<span id="array-as-func-arg"></span>[array as function
argument](#array-as-func-arg-note)

<span style="color: gray">*parameter contains address copy*</span>

<span style="color: gray">*parameter contains address copy*</span>

<span style="color: gray">*parameter contains deep copy*</span>

<span style="color: gray">*parameter contains address copy*</span>

<span id="iterate-over-array"></span>[iterate over
elements](#iterate-over-array-note)  
<span style="white-space: pre-wrap;"> </span>

\[6, 7, 8\].forEach((n) =\> {  
<span style="white-space: pre-wrap;">  </span>console.log(n);  
});  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
new in ES6:</span>  
for (let n of \[6, 7, 8\]) {  
<span style="white-space: pre-wrap;">  </span>console.log(n);  
}

for i in \[1, 2, 3\]:  
<span style="white-space: pre-wrap;">  </span>print(i)

foreach (\[1, 2, 3\] as $i) {  
<span style="white-space: pre-wrap;">  </span>echo "$i\\n";  
}

\[1, 2, 3\].each { |i| puts i }

<span id="indexed-array-iteration"></span>[iterate over indices and
elements](#indexed-array-iteration-note)

for (let i = 0; i \< a.length; ++i) {  
<span style="white-space: pre-wrap;">  </span>console.log(a\[i\]);  
}  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
indices not guaranteed to be in order:</span>  
for (let i in a) {  
<span style="white-space: pre-wrap;">  </span>console.log(a\[i\]);  
}

a = \['do', 're', 'mi', 'fa'\]  
for i, s in enumerate(a):  
<span style="white-space: pre-wrap;">  </span>print('%s at index %d' %
(s, i))

$a = \["do", "re", "mi" "fa"\];  
foreach ($a as $i =\> $s) {  
<span style="white-space: pre-wrap;">  </span>echo "$s at index
$i\\n";  
}

a = %w(do re mi fa)  
a.each\_with\_index do |s, i|  
<span style="white-space: pre-wrap;">  </span>puts "\#{s} at index
\#{i}"  
end

<span id="range-iteration"></span>[iterate over
range](#range-iteration-note)

<span style="color: gray">*not space efficient; use C-style for
loop*</span>

<span style="color: gray">\# use range() in Python 3:</span>  
for i in xrange(1,
1000001):  
<span style="white-space: pre-wrap;">  </span><span style="color: gray">*code*</span>

<span style="color: gray">*not space efficient; use C-style for
loop*</span>

(1..1\_000\_000).each do
|i|  
<span style="white-space: pre-wrap;">  </span><span style="color: gray">*code*</span>  
end

<span id="range-array"></span>[instantiate range as
array](#range-array-note)

let a = \_.range(1, 11);

a = range(1, 11)  
<span style="color: gray">*Python 3:*</span>  
a = list(range(1, 11))

$a = range(1, 10);

a = (1..10).to\_a

<span id="array-reverse"></span>[reverse](#array-reverse-note)  
<span style="color: gray">*non-destructive, in-place*</span>

let a = \[1, 2, 3\];  
  
let a2 = a.slice(0).reverse();  
a.reverse();

a = \[1, 2, 3\]  
  
a\[::-1\]  
a.reverse()

$a = \[1, 2, 3\];  
  
array\_reverse($a);  
$a = array\_reverse($a);

a = \[1, 2, 3\]  
  
a.reverse  
a.reverse\!

<span id="array-sort"></span>[sort](#array-sort-note)  
<span style="color: gray">*non-destructive,  
in-place,  
custom comparision*</span>

let a = \[3, 1, 4, 2\];  
  
let a2 = a.slice(0).sort();  
a.sort();

a = \['b', 'A', 'a', 'B'\]  
  
sorted(a)  
a.sort()  
<span style="color: gray">\# custom binary comparision  
\# removed from Python 3:</span>  
a.sort(key=str.lower)

$a = \["b", "A", "a", "B"\];  
  
<span style="color: gray">*none*</span>  
sort($a);  
<span style="color: gray">*none, but* usort *sorts in place*</span>

a = %w(b A a B)  
  
a.sort  
a.sort\!  
a.sort do |x, y|  
<span style="white-space: pre-wrap;">  </span>x.downcase \<=\>
y.downcase  
end

<span id="array-dedupe"></span>[dedupe](#array-dedupe-note)  
<span style="color: gray">*non-destructive, in-place*</span>

let a = \[1, 2, 2, 3\];  
  
let a2 = \_.uniq(a);  
a = \_.uniq(a);

a = \[1, 2, 2, 3\]  
  
a2 = list(set(a))  
a = list(set(a))

$a = \[1, 2, 2, 3\];  
  
$a2 = array\_unique($a);  
$a = array\_unique($a);

a = \[1, 2, 2, 3\]  
  
a2 = a.uniq  
a.uniq\!

<span id="membership"></span>[membership](#membership-note)  
<span style="white-space: pre-wrap;"> </span>

a.includes(7)

7 in a

in\_array(7, $a)

a.include?(7)

<span id="intersection"></span>[intersection](#intersection-note)  
<span style="white-space: pre-wrap;"> </span>

\_.intersection(\[1, 2\], \[2, 3, 4\])

{1, 2} & {2, 3, 4}

$a = \[1, 2\];  
$b = \[2, 3, 4\]  
array\_intersect($a, $b)

\[1, 2\] & \[2 ,3, 4\]

<span id="union"></span>[union](#union-note)  
<span style="white-space: pre-wrap;"> </span>

\_.union(\[1, 2\], \[2, 3, 4\])

{1, 2} | {2, 3, 4}

$a1 = \[1, 2\];  
$a2 = \[2, 3, 4\];  
array\_unique(array\_merge($a1, $a2))

\[1, 2\] | \[2, 3, 4\]

<span id="set-diff"></span>[relative complement, symmetric
difference](#set-diff-note)

\_.difference(\[1, 2, 3\], \[2\])  
<span style="color: gray">*none*</span>

{1, 2, 3} - {2}  
{1, 2} ^ {2, 3, 4}

$a1 = \[1, 2, 3\];  
$a2 = \[2\];  
array\_values(array\_diff($a1, $a2))  
<span style="color: gray">*none*</span>

require 'set'  
  
\[1, 2, 3\] - \[2\]  
Set\[1, 2\] ^ Set\[2 ,3, 4\]

<span id="map"></span>[map](#map-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
callback gets 3 args:  
<span style="white-space: pre-wrap;">//</span> value, index,
array</span>  
a.map((x) =\> x \* x)

map(lambda x: x \* x, \[1, 2, 3\])  
<span style="color: gray">\# or use list comprehension:</span>  
\[x \* x for x in \[1, 2, 3\]\]

array\_map(function ($x)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>return
$x \* $x;  
<span style="white-space: pre-wrap;">  </span>}, \[1, 2, 3\])

\[1, 2, 3\].map { |o| o \* o }

<span id="filter"></span>[filter](#filter-note)  
<span style="white-space: pre-wrap;"> </span>

a.filter((x) =\> x \> 1)

filter(lambda x: x \> 1, \[1, 2, 3\])  
<span style="color: gray">\# or use list comprehension:</span>  
\[x for x in \[1, 2, 3\] if x \> 1\]

array\_filter(\[1, 2, 3\],  
<span style="white-space: pre-wrap;">  </span>function ($x)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>return
$x\>1;  
<span style="white-space: pre-wrap;">  </span>})

\[1, 2, 3\].select { |o| o \> 1 }

<span id="reduce"></span>[reduce](#reduce-note)  
<span style="white-space: pre-wrap;"> </span>

a.reduce((m, o) =\> m + o, 0)

<span style="color: gray">\# import needed in Python 3 only</span>  
from functools import reduce  
  
reduce(lambda x, y: x + y, \[1, 2, 3\], 0)

array\_reduce(\[1, 2, 3\],  
<span style="white-space: pre-wrap;">  </span>function($x,$y)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>return
$x + $y;  
<span style="white-space: pre-wrap;">  </span>}, 0)

\[1, 2, 3\].inject(0) { |m, o| m + o }

<span id="universal-existential-test"></span>[universal and existential
tests](#universal-existential-test-note)  
<span style="white-space: pre-wrap;"> </span>

let a = \[1, 2, 3, 4\];  
  
a.every((n) =\> n % 2 === 0)  
a.some((n) =\> n % 2 === 0)

all(i % 2 == 0 for i in \[1, 2, 3, 4\])  
any(i % 2 == 0 for i in \[1, 2, 3, 4\])

<span style="color: gray">*use array\_filter*</span>

\[1, 2, 3, 4\].all? {|i| i.even? }  
\[1, 2, 3, 4\].any? {|i| i.even? }

<span id="shuffle-sample"></span>[shuffle and
sample](#shuffle-sample-note)

let a = \[1, 2, 3, 4\];  
  
a = \_.shuffle(a);  
let samp = \_.sampleSize(\[1, 2, 3, 4\], 2);

from random import shuffle, sample  
  
a = \[1, 2, 3, 4\]  
shuffle(a)  
samp = sample(\[1, 2, 3, 4\], 2)

$a = \[1, 2, 3, 4\];  
  
shuffle($a);  
$samp = array\_rand(|\[1, 2, 3, 4\], 2);

\[1, 2, 3, 4\].shuffle\!  
samp = \[1, 2, 3, 4\].sample(2)

<span id="flatten"></span>[flatten](#flatten-note)  
<span style="color: gray">*one level, completely*</span>

let a = \[1, \[2, \[3, 4\]\]\];  
  
let a2 = \_.flatten(a);  
let a3 = \_.flattenDeep(a);

<span style="color: gray">*none*</span>

<span style="color: gray">*none*</span>

a = \[1, \[2, \[3, 4\]\]\]  
a2 = a.flatten(1)  
a3 = a.flatten

<span id="zip"></span>[zip](#zip-note)  
<span style="white-space: pre-wrap;"> </span>

let a = \_.zip(\[1, 2, 3\], \['a', 'b', 'c'\]);  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
shorter array padded with undefined:</span>  
\_.zip(\[1, 2, 3\], \['a', 'b'\])

list(zip(\[1, 2, 3\], \['a', 'b', 'c'\]))  
  
<span style="color: gray">\# extras in longer array dropped:</span>  
list(zip(\[1, 2, 3\], \['a', 'b'\]))

$a = array\_map(NULL,  
<span style="white-space: pre-wrap;">  </span>\[1, 2, 3\],  
<span style="white-space: pre-wrap;">  </span>\["a", "b", "c"\]);  
  
<span style="color: gray">\# shorter array padded with NULLs</span>

\[1, 2, 3\].zip(\["a", "b", "c"\])  
  
<span style="color: gray">\# shorter array padded with nil:</span>  
\[1, 2, 3\].zip(\["a", "b"\])

<span id="dictionaries"></span>[dictionaries](#dictionaries-note)

node.js

python

php

ruby

<span id="dict-literal"></span>[literal](#dict-literal-note)  
<span style="white-space: pre-wrap;"> </span>

d = {t: 1, f: 0};  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
keys do not need to be quoted if they  
<span style="white-space: pre-wrap;">//</span> are a legal JavaScript
variable name  
<span style="white-space: pre-wrap;">//</span> and not a reserved
word</span>

d = {'t': 1, 'f': 0}

$d = \["t" =\> 1, "f" =\> 0\];  
  
<span style="color: gray">\# older syntax:</span>  
$d = array("t" =\> 1, "f" =\> 0);

d = {'t' =\> 1, 'f' =\> 0}  
  
<span style="color: gray">\# keys are symbols:</span>  
symbol\_to\_int = {t: 1, f: 0}

<span id="dict-size"></span>[size](#dict-size-note)  
<span style="white-space: pre-wrap;"> </span>

\_.size(d)  
Object.getOwnPropertyNames(d).length

len(d)

count($d)

d.size  
d.length

<span id="dict-lookup"></span>[lookup](#dict-lookup-note)  
<span style="white-space: pre-wrap;"> </span>

d.hasOwnProperty("t") ? d\["t"\] : undefined  
d.hasOwnProperty("t") ? d.t : undefined  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
JavaScript dictionaries are objects  
<span style="white-space: pre-wrap;">//</span> and inherit properties
from Object.</span>

d\['t'\]

$d\["t"\]

d\['t'\]

<span id="dict-update"></span>[update](#dict-update-note)

d\['t'\] = 2;  
d.t = 2;

d\['t'\] = 2  
  
<span style="color: gray">\# provide default to avoid KeyError:</span>  
d.get('t', None)

$d\["t"\] = 2;

d\['t'\] = 2

<span id="dict-missing-key"></span>[missing key
behavior](#dict-missing-key-note)  
<span style="white-space: pre-wrap;"> </span>

let d = {};  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
undefined:</span>  
d\["lorem"\];  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
adds key/value pair:</span>  
d\["lorem"\] = "ipsum";

d = {}  
<span style="color: gray">\# raises KeyError:</span>  
d\['lorem'\]  
<span style="color: gray">\# adds key/value pair:</span>  
d\['lorem'\] = 'ipsum'

$d = \[\];  
<span style="color: gray">\# NULL:</span>  
$d\["lorem"\];  
<span style="color: gray">\# adds key/value pair:</span>  
$d\["lorem"\] = "ipsum";

d = {}  
<span style="color: gray">\# nil:</span>  
d\['lorem'\]  
<span style="color: gray">\# adds key/value pair:</span>  
d\['lorem'\] = 'ipsum'

<span id="dict-key-check"></span>[is key
present](#dict-key-check-note)  
<span style="white-space: pre-wrap;"> </span>

d.hasOwnProperty("t");

'y' in d

array\_key\_exists("y", $d);

d.key?('y')

<span id="dict-delete"></span>[delete](#dict-delete-note)

delete d\["t"\];  
delete d.t;

d = {1: True, 0: False}  
del d\[1\]

$d = \[1 =\> "t", 0 =\> "f"\];  
unset($d\[1\]);

d = {1 =\> true, 0 =\> false}  
d.delete(1)

<span id="dict-assoc-array"></span>[from array of pairs, from even
length array](#dict-assoc-array-note)

let a = \[\['a', 1\], \['b', 2\], \['c', 3\]\];  
let d = \_.fromPairs(a);  
  
<span style="color: gray">*none*</span>

a = \[\['a', 1\], \['b', 2\], \['c', 3\]\]  
d = dict(a)  
  
a = \['a', 1, 'b', 2, 'c', 3\]  
d = dict(zip(a\[::2\], a\[1::2\]))

a = \[\['a', 1\], \['b', 2\], \['c', 3\]\]  
d = Hash\[a\]  
  
a = \['a', 1, 'b', 2, 'c', 3\]  
d = Hash\[\*a\]

<span id="dict-merge"></span>[merge](#dict-merge-note)

let d1 = {a: 1, b: 2};  
let d2 = {b: 3, c: 4};  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
d2 overwrites shared keys in d1:</span>  
d1 = \_.assignIn(d1, d2);

d1 = {'a': 1, 'b': 2}  
d2 = {'b': 3, 'c': 4}  
d1.update(d2)

$d1 = \["a" =\> 1, "b" =\> 2\];  
$d2 = \["b" =\> 3, "c" =\> 4\];  
$d1 = array\_merge($d1, $d2);

d1 = {'a' =\> 1, 'b' =\> 2}  
d2 = {'b' =\> 3, 'c' =\> 4}  
d1.merge\!(d2)

<span id="dict-invert"></span>[invert](#dict-invert-note)

let let2num = {t: 1, f: 0};  
let num2let = \_.invert(let2num);

to\_num = {'t': 1, 'f': 0}  
<span style="color: gray">\# dict comprehensions added in 2.7:</span>  
to\_let = {v: k for k, v  
<span style="white-space: pre-wrap;">  </span>in to\_num.items()}

$to\_num = \["t" =\> 1, "f" =\> 0\];  
$to\_let = array\_flip($to\_num);

to\_num = {'t' =\> 1, 'f' =\> 0}  
to\_let = to\_num.invert

<span id="dict-iter"></span>[iterate](#dict-iter-note)  
<span style="white-space: pre-wrap;"> </span>

for (let k in d)
{  
<span style="white-space: pre-wrap;">  </span>console.log(<span style="white-space: pre-wrap;">\`</span>value
at ${k} is ${d\[k\]}<span style="white-space: pre-wrap;">\`</span>);  
}

for k, v in d.items():  
<span style="white-space: pre-wrap;">  </span>print('value at {} is
{}'.format(k, v)  
  
<span style="color: gray">\# Python 2: use iteritems()</span>

foreach ($d as $k =\> $v) {  
<span style="white-space: pre-wrap;">  </span>echo "value at ${k} is
${v}";  
}

d.each do |k,v|  
<span style="white-space: pre-wrap;">  </span>puts "value at \#{k} is
\#{v}"  
end

<span id="dict-key-val"></span>[keys and values as
arrays](#dict-key-val-note)

Object.keys(d)  
\_.values(d)

list(d.keys())  
list(d.values())  
  
<span style="color: gray">\# keys() and values return iterators  
\# in Python 3 and lists in Python 2</span>

array\_keys($d)  
array\_values($d)

d.keys  
d.values

<span id="dict-sort-values"></span>[sort by
values](#dict-sort-values-note)

let cmp = (a, b) =\> a\[1\] - b\[1\];  
let d = {t: 1, f: 0};  
  
for (let p of \_.toPairs(d).sort(cmp)) {  
<span style="white-space: pre-wrap;">  </span>console.log(p);  
}

from operator import itemgetter  
  
pairs = sorted(d.items(), key=itemgetter(1))  
  
for k, v in pairs:  
<span style="white-space: pre-wrap;">  </span>print('{}: {}'.format(k,
v))

asort($d);  
  
foreach ($d as $k =\> $v) {  
<span style="white-space: pre-wrap;">  </span>print "$k: $v\\n";  
}

d.sort\_by { |k, v| v }.each do |k, v|  
<span style="white-space: pre-wrap;">  </span>puts "\#{k}: \#{v}"  
end

<span id="dict-default-val"></span>[default value, computed
value](#dict-default-val-note)

<span style="color: gray">*none*</span>

from collections import defaultdict  
  
counts = defaultdict(lambda: 0)  
counts\['foo'\] += 1  
  
class Factorial(dict):  
<span style="white-space: pre-wrap;">  </span>def
<span style="white-space: pre-wrap;">\_\_missing\_\_</span>(self,
k):  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>if
k \>
1:  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>return
k \*
self\[k-1\]  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>else:  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>return
1  
  
factorial = Factorial()

$counts = \[\];  
$counts\['foo'\] += 1;  
  
<span style="color: gray">\# For computed values and defaults other
than  
\# zero or empty string, extend ArrayObject.</span>

counts = Hash.new(0)  
counts\['foo'\] += 1  
  
factorial = Hash.new do |h,k|  
<span style="white-space: pre-wrap;">  </span>k \> 1 ? k \* h\[k-1\] :
1  
end

<span id="functions"></span>[functions](#functions-note)

node.js

python

php

ruby

<span id="def-func"></span>[define](#def-func-note)  
<span style="white-space: pre-wrap;"> </span>

function add3 (x1, x2, x3) {  
<span style="white-space: pre-wrap;">  </span>return x1 + x2 + x3;  
}

def add3(x1, x2, x3):  
<span style="white-space: pre-wrap;">  </span>return x1 + x2 + x3

function add3($x1, $x2, $x3)  
{  
<span style="white-space: pre-wrap;">  </span>return $x1 + $x2 + $x3;  
}

def add3(x1, x2, x3)  
<span style="white-space: pre-wrap;">  </span>x1 + x2 + x3  
end  
  
<span style="color: gray">\# parens are optional and customarily  
\# omitted when defining functions  
\# with no parameters</span>

<span id="invoke-func"></span>[invoke](#invoke-func-note)

add3(1, 2, 3)

add3(1, 2, 3)

add3(1, 2, 3);  
  
<span style="color: gray">\# function names are case
insensitive:</span>  
ADD3(1, 2, 3);

add3(1, 2, 3)  
  
<span style="color: gray">\# parens are optional:</span>  
add3 1, 2, 3

<span id="missing-arg"></span>[missing argument
behavior](#missing-arg-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*set to* undefined</span>

<span style="color: gray">*raises* TypeError *if number of arguments
doesn't match function arity*</span>

<span style="color: gray">*set to* NULL *with warning*</span>

<span style="color: gray">*raises* ArgumentError *if number of arguments
doesn't match function arity*</span>

<span id="extra-arg"></span>[extra argument behavior](#extra-arg-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*ignored*</span>

<span style="color: gray">*raises* TypeError *if number of arguments
doesn't match function arity*</span>

<span style="color: gray">*ignored*</span>

<span style="color: gray">*raises* ArgumentError *if number of arguments
doesn't match function arity*</span>

<span id="default-arg"></span>[default argument](#default-arg-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
new in ES6:</span>  
function myLog (x, base = 10) {  
<span style="white-space: pre-wrap;">  </span>return Math.log(x) /
Math.log(base);  
}

import math  
  
def my\_log(x, base=10):  
<span style="white-space: pre-wrap;">  </span>return math.log(x) /
math.log(base)  
  
my\_log(42)  
my\_log(42, math.e)

function my\_log($x, $base=10)  
{  
<span style="white-space: pre-wrap;">  </span>return log($x) /
log($base);  
}  
  
my\_log(42);  
my\_log(42, M\_E);

def my\_log(x, base=10)  
<span style="white-space: pre-wrap;">  </span>Math.log(x) /
Math.log(base)  
end  
  
my\_log(42)  
my\_log(42, Math::E)

<span id="variadic-func"></span>[variadic function](#variadic-func-note)

function firstAndLast() {  
<span style="white-space: pre-wrap;">  </span>if (arguments.length \>=
1)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>console.log('first:
' + arguments\[0\]);  
<span style="white-space: pre-wrap;">  </span>}  
<span style="white-space: pre-wrap;">  </span>if (arguments.length \>=
2)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>console.log('last:
' + arguments\[1\]);  
<span style="white-space: pre-wrap;">  </span>}  
}  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//
...</span> operator new in ES6:</span>  
function firstAndLast(<span style="white-space: pre-wrap;">...</span>a)
{  
<span style="white-space: pre-wrap;">  </span>if (a.length \>= 1)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>console.log('first:
' + a\[0\]);  
<span style="white-space: pre-wrap;">  </span>}  
<span style="white-space: pre-wrap;">  </span>if (a.length \>= 2)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>console.log('last:
' + a\[1\]);  
<span style="white-space: pre-wrap;">  </span>}  
}

def first\_and\_last(\*a):  
  
<span style="white-space: pre-wrap;">  </span>if len(a) \>=
1:  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>print('first:
' + str(a\[0\]))  
  
<span style="white-space: pre-wrap;">  </span>if len(a) \>=
2:  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>print('last:
' + str(a\[-1\]))

function first\_and\_last()  
{  
  
<span style="white-space: pre-wrap;">  </span>$arg\_cnt =
func\_num\_args();  
  
<span style="white-space: pre-wrap;">  </span>if ($arg\_cnt \>= 1)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>$n
=
func\_get\_arg(0);  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>echo
"first: " . $n . "\\n";  
<span style="white-space: pre-wrap;">  </span>}  
  
<span style="white-space: pre-wrap;">  </span>if ($arg\_cnt \>= 2)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>$a
=
func\_get\_args();  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>$n
=
$a\[$arg\_cnt-1\];  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>echo
"last: " . $n . "\\n";  
<span style="white-space: pre-wrap;">  </span>}  
}

def first\_and\_last(\*a)  
  
<span style="white-space: pre-wrap;">  </span>if a.size \>=
1  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>puts
"first: \#{a\[0\]}"  
<span style="white-space: pre-wrap;">  </span>end  
  
<span style="white-space: pre-wrap;">  </span>if a.size \>=
2  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>puts
"last: \#{a\[-1\]}"  
<span style="white-space: pre-wrap;">  </span>end  
end

<span id="apply-func"></span>[pass array elements as separate
arguments](#apply-func-note)

let a = \[1, 2, 3\];  
  
let sum = add3(<span style="white-space: pre-wrap;">...</span>a);

a = \[2, 3\]  
  
add3(1, \*a)  
  
<span style="color: gray">\# splat operator can only be used once  
\# and must appear after other  
\# unnamed arguments</span>

$a = \[1, 2, 3\];  
  
call\_user\_func\_array("add3", $a);

a = \[2, 3\]  
  
add3(1, \*a)  
  
<span style="color: gray">\# splat operator can be used multiple  
\# times and can appear before regular  
\# arguments</span>

<span id="param-alias"></span>[parameter alias](#param-alias-note)

<span style="color: gray">*none*</span>

<span style="color: gray">*none*</span>

function first\_and\_second(&$a)  
{  
<span style="white-space: pre-wrap;">  </span>return \[$a\[0\],
$a\[1\]\];  
}

<span style="color: gray">*none*</span>

<span id="named-param"></span>[named parameters](#named-param-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*none*</span>

def fequal(x, y, eps=0.01):  
<span style="white-space: pre-wrap;">  </span>return abs(x - y) \< eps  
  
fequal(1.0, 1.001)  
fequal(1.0, 1.001,
eps=0.1<span style="white-space: pre-wrap;">\*\*</span>10)

<span style="color: gray">*none*</span>

def fequals(x, y, eps: 0.01)  
<span style="white-space: pre-wrap;">  </span>(x - y).abs \< eps  
end  
  
fequals(1.0, 1.001)  
fequals(1.0, 1.001, eps: 0.1\*\*10)

<span id="retval"></span>[return value](#retval-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">return *arg or* undefined.</span>  
  
<span style="color: gray">*If invoked with* new *and* return *value not
an object, returns* this.</span>

<span style="color: gray">return *arg or* None</span>

<span style="color: gray">return *arg or* NULL</span>

<span style="color: gray">return *arg or last expression
evaluated*</span>

<span id="multiple-retval"></span>[multiple return
values](#multiple-retval-note)  
<span style="white-space: pre-wrap;"> </span>

function firstAndSecond(a) {  
<span style="white-space: pre-wrap;">  </span>return \[a\[0\],
a\[1\]\];  
}  
  
let \[x, y\] = firstAndSecond(\[6, 7, 8\]);  

def first\_and\_second(a):  
<span style="white-space: pre-wrap;">  </span>return a\[0\], a\[1\]  
  
x, y = first\_and\_second(\[6, 7, 8\])

function first\_and\_second(&$a)  
{  
<span style="white-space: pre-wrap;">  </span>return \[$a\[0\],
$a\[1\]\];  
}  
  
$a = \[6, 7, 8\];  
list($x, $y) =  
<span style="white-space: pre-wrap;">  </span>first\_and\_second($a);

def first\_and\_second(a)  
<span style="white-space: pre-wrap;">  </span>return a\[0\], a\[1\]  
end  
  
x, y = first\_and\_second(\[6, 7, 8\])

<span id="anonymous-func-literal"></span>[anonymous function
literal](#anonymous-func-literal-note)  
<span style="white-space: pre-wrap;"> </span>

let square = function (x) {  
<span style="white-space: pre-wrap;">  </span>return x \* x;  
};  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
=\> new in ES6:</span>  
let square = (x) =\> { return x \* x; };  
  
<span style="color: gray"><span style="white-space: pre-wrap;">//</span>
expression body variant:</span>  
let square = (x) =\> x \* x;

<span style="color: gray">\# body must be an expression:</span>  
square = lambda x: x \* x

$square = function ($x) {  
<span style="white-space: pre-wrap;">  </span>return $x \* $x;  
};

square = lambda { |x| x \* x }

<span id="invoke-anonymous-func"></span>[invoke anonymous
function](#invoke-anonymous-func-note)

square(2)  
  
((x) =\> (x \* x)(2)

square(2)  
  
(lambda x: x \* x)(2)

$square(2)

square.call(2)  
  
<span style="color: gray">\# alternative syntax:</span>  
square\[2\]

<span id="func-as-val"></span>[function as value](#func-as-val-note)  
<span style="white-space: pre-wrap;"> </span>

let func = add3;

func = add3

$func = "add3";

func = lambda { |\*args| add3(\*args) }

<span id="private-state-func"></span>[function with private
state](#private-state-func-note)

function counter() {  
<span style="white-space: pre-wrap;">  </span>counter.i += 1;  
<span style="white-space: pre-wrap;">  </span>return counter.i;  
}  
  
counter.i = 0;  
console.log(counter());

<span style="color: gray">\# state not private:</span>  
def counter():  
<span style="white-space: pre-wrap;">  </span>counter.i += 1  
<span style="white-space: pre-wrap;">  </span>return counter.i  
  
counter.i = 0  
print(counter())

function counter()  
{  
<span style="white-space: pre-wrap;">  </span>static $i = 0;  
<span style="white-space: pre-wrap;">  </span>return ++$i;  
}  
  
echo counter();

<span style="color: gray">*none*</span>

<span id="closure"></span>[closure](#closure-note)

function makeCounter () {  
<span style="white-space: pre-wrap;">  </span>let i = 0;  
  
<span style="white-space: pre-wrap;">  </span>return function ()
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>i
+=
1;  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>return
i;  
<span style="white-space: pre-wrap;">  </span>};  
}  
  
let nays = makeCounter();  
console.log(nays());

def make\_counter():  
<span style="white-space: pre-wrap;">  </span>i = 0  
<span style="white-space: pre-wrap;">  </span>def
counter():  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="color: gray">\#
new in Python
3:</span>  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>nonlocal
i  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>i
+=
1  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>return
i  
<span style="white-space: pre-wrap;">  </span>return counter  
  
nays = make\_counter()  
print(nays())

function make\_counter()  
{  
<span style="white-space: pre-wrap;">  </span>$i = 0;  
<span style="white-space: pre-wrap;">  </span>return function () use
(&$i)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>return
++$i;  
<span style="white-space: pre-wrap;">  </span>};  
}  
  
$nays = make\_counter();  
echo $nays();

def make\_counter  
<span style="white-space: pre-wrap;">  </span>i = 0  
<span style="white-space: pre-wrap;">  </span>return lambda { i +=1; i
}  
end  
  
nays = make\_counter  
puts nays.call

<span id="generator"></span>[generator](#generator-note)

function \* makeCounter () {  
<span style="white-space: pre-wrap;">  </span>let i = 0;  
<span style="white-space: pre-wrap;">  </span>while (true)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>yield
++i;  
<span style="white-space: pre-wrap;">  </span>}  
}  
  
let nays = makeCounter();  
for (let cnt of nays) {  
<span style="white-space: pre-wrap;">  </span>console.log(cnt);  
<span style="white-space: pre-wrap;">  </span>if (cnt \> 100)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>break;  
<span style="white-space: pre-wrap;">  </span>}  
}

<span style="color: gray">\# cf. itertools library</span>  
  
def make\_counter():  
<span style="white-space: pre-wrap;">  </span>i = 0  
<span style="white-space: pre-wrap;">  </span>while
True:  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>i
+=
1  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>yield
i  
  
nays = make\_counter()  
<span style="color: gray">\# Python 2: nays.next()</span>  
print(next(nays))  
  
for cnt in nays:  
<span style="white-space: pre-wrap;">  </span>print(cnt)  
<span style="white-space: pre-wrap;">  </span>if cnt \>
100:  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>break  
  
<span style="color: gray">\# Returning without yielding raises  
\# StopIteration exception.</span>

<span style="color: gray">\# PHP 5.5:</span>  
function make\_counter() {  
<span style="white-space: pre-wrap;">  </span>$i = 0;  
<span style="white-space: pre-wrap;">  </span>while (1)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>yield
++$i;  
<span style="white-space: pre-wrap;">  </span>}  
}  
  
$nays = make\_counter();  
<span style="color: gray">\# does not return a value:</span>  
$nays-\>next();  
<span style="color: gray">\# runs generator if generator has not  
\# yet yielded:</span>  
echo $nays-\>current();

def make\_counter  
<span style="white-space: pre-wrap;">  </span>return Fiber.new
do  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>i
=
0  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>while
true  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>i
+=
1  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>Fiber.yield
i  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>end  
<span style="white-space: pre-wrap;">  </span>end  
end  
  
nays = make\_counter  
puts nays.resume

<span id="decorator"></span>[decorator](#decorator-note)

<span style="color: gray">*none*</span>

def logcall(f):  
<span style="white-space: pre-wrap;">  </span>def wrapper(\*a,
\*\*opts):  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>print('calling
' +
f.<span style="white-space: pre-wrap;">\_\_name\_\_</span>)  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>f(\*a,
\*\*opts)  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>print('called
' + f.<span style="white-space: pre-wrap;">\_\_name\_\_</span>)  
<span style="white-space: pre-wrap;">  </span>return wrapper  
  
@logcall  
def square(x):  
<span style="white-space: pre-wrap;">  </span>return x \* x

<span id="invoke-op-like-func"></span>[invoke operator like
function](#invoke-op-like-func-note)

<span style="color: gray">*none*</span>

import operator  
  
operator.mul(3, 7)  
  
a = \['foo', 'bar', 'baz'\]  
operator.itemgetter(2)(a)

3.\*(7)  
  
a = \['foo', 'bar', 'baz'\]  
a.\[\](2)

<span id="execution-control"></span>[execution
control](#execution-control-note)

node.js

python

php

ruby

<span id="if"></span>[if](#if-note)  
<span style="white-space: pre-wrap;"> </span>

if (n === 0) {  
<span style="white-space: pre-wrap;">  </span>console.log('no hits');  
} else if (n === 1) {  
<span style="white-space: pre-wrap;">  </span>console.log('1 hit');  
} else {  
<span style="white-space: pre-wrap;">  </span>console.log(n + '
hits');  
}

if 0 == n:  
<span style="white-space: pre-wrap;">  </span>print('no hits')  
elif 1 == n:  
<span style="white-space: pre-wrap;">  </span>print('one hit')  
else:  
<span style="white-space: pre-wrap;">  </span>print(str(n) + ' hits')

if ( 0 == $n ) {  
<span style="white-space: pre-wrap;">  </span>echo "no hits\\n";  
} elseif ( 1 == $n ) {  
<span style="white-space: pre-wrap;">  </span>echo "one hit\\n";  
} else {  
<span style="white-space: pre-wrap;">  </span>echo "$n hits\\n";  
}

if n == 0  
<span style="white-space: pre-wrap;">  </span>puts "no hits"  
elsif 1 == n  
<span style="white-space: pre-wrap;">  </span>puts "one hit"  
else  
<span style="white-space: pre-wrap;">  </span>puts "\#{n} hits"  
end

<span id="switch"></span>[switch](#switch-note)

switch (n) {  
case 0:  
<span style="white-space: pre-wrap;">  </span>console.log('no
hits\\n;);  
<span style="white-space: pre-wrap;">  </span>break;  
case 1:  
<span style="white-space: pre-wrap;">  </span>console.log('one
hit\\n');  
<span style="white-space: pre-wrap;">  </span>break;  
default:  
<span style="white-space: pre-wrap;">  </span>console.log(n + '
hits\\n');  
}

<span style="color: gray">*none*</span>

switch ($n) {  
case 0:  
<span style="white-space: pre-wrap;">  </span>echo "no hits\\n";  
<span style="white-space: pre-wrap;">  </span>break;  
case 1:  
<span style="white-space: pre-wrap;">  </span>echo "one hit\\n";  
<span style="white-space: pre-wrap;">  </span>break;  
default:  
<span style="white-space: pre-wrap;">  </span>echo "$n hits\\n";  
}

case n  
when 0  
<span style="white-space: pre-wrap;">  </span>puts "no hits"  
when 1  
<span style="white-space: pre-wrap;">  </span>puts "one hit"  
else  
<span style="white-space: pre-wrap;">  </span>puts "\#{n} hits"  
end

<span id="while"></span>[while](#while-note)  
<span style="white-space: pre-wrap;"> </span>

while (i \< 100) {  
<span style="white-space: pre-wrap;">  </span>i += 1;  
}

while i \< 100:  
<span style="white-space: pre-wrap;">  </span>i += 1

while ( $i \< 100 ) { $i++; }

while i \< 100 do  
<span style="white-space: pre-wrap;">  </span>i += 1  
end

<span id="for"></span>[for](#for-note)  
<span style="white-space: pre-wrap;"> </span>

for (let i = 0; i \< 10; ++i) {  
<span style="white-space: pre-wrap;">  </span>console.log(i);  
}

for i in range(1, 11):  
<span style="white-space: pre-wrap;">  </span>print(i)

for ($i = 1; $i \<= 10; $i++) {  
<span style="white-space: pre-wrap;">  </span>echo "$i\\n";  
}

<span style="color: gray">*none*</span>

<span id="break"></span>[break](#break-note)  
<span style="white-space: pre-wrap;"> </span>

for (let i = 30; i \< 50; ++i) {  
<span style="white-space: pre-wrap;">  </span>if (i % 7 === 0)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>console.log('first
multiple: ' +
i);  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>break;  
<span style="white-space: pre-wrap;">  </span>}  
}

break

break

break

<span id="continue"></span>[continue](#continue-note)  
<span style="white-space: pre-wrap;"> </span>

for (let i = 30; i \< 50; ++i) {  
<span style="white-space: pre-wrap;">  </span>if (i % 7 === 0)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>continue;  
<span style="white-space: pre-wrap;">  </span>}  
<span style="white-space: pre-wrap;">  </span>console.log('not
divisible: ' + i);  
}

continue

continue

next

<span id="statement-modifiers"></span>[statement
modifiers](#statement-modifiers-note)  
<span style="white-space: pre-wrap;"> </span>

<span style="color: gray">*none*</span>

<span style="color: gray">*none*</span>

<span style="color: gray">*none*</span>

puts "positive" if i \> 0  
puts "nonzero" unless i == 0

<span id="exceptions"></span>[exceptions](#exceptions-note)

node.js

python

php

ruby

<span id="base-exc"></span>[base exception](#base-exc-note)

<span style="color: gray">*Any value can be thrown.*</span>

BaseException  
  
<span style="color: gray">*User-defined exceptions should subclass*
Exception.</span>  
  
<span style="color: gray">*In Python 2 old-style classes can be
thrown.*</span>

Exception

Exception  
  
<span style="color: gray">*User-defined exceptions should subclass*
StandardError.</span>

<span id="predefined-exc"></span>[predefined
exceptions](#predefined-exc-note)

Error  
<span style="white-space: pre-wrap;">  </span>EvalError  
<span style="white-space: pre-wrap;">  </span>RangeError  
<span style="white-space: pre-wrap;">  </span>ReferenceError  
<span style="white-space: pre-wrap;">  </span>SyntaxError  
<span style="white-space: pre-wrap;">  </span>TypeError  
<span style="white-space: pre-wrap;">  </span>URIError

BaseException  
<span style="white-space: pre-wrap;">  </span>Exception  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>TypeError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>ImportError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>AssertionError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>ArithmeticError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>FloatingPointError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>OverflowError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>ZeroDivisionError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>SyntaxError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>OSError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>MemoryError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>StopIteration  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>Error  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>SystemError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>ValueError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>UnicodeError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>UnicodeEncodeError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>UnicodeDecodeError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>UnicodeTranslateError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>UnsupportedOperation  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>NameError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>AttributeError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>RuntimeError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>LookupError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>IndexError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>KeyError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>EOFError  
<span style="white-space: pre-wrap;">  </span>GeneratorExit  
<span style="white-space: pre-wrap;">  </span>KeyboardInterrupt  
<span style="white-space: pre-wrap;">  </span>SystemExit

Exception  
<span style="white-space: pre-wrap;">  </span>LogicException  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>BadFunctionCallException  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>BadMethodCallException  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>DomainException  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>InvalidArgumentException  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>LengthException  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>OutOfRangeException  
<span style="white-space: pre-wrap;">  </span>RuntimeException  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>OutOfBoundsException  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>OverflowException  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>RangeException  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>UnderflowException  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>UnexpectedValueException

Exception  
<span style="white-space: pre-wrap;">  </span>NoMemoryError  
<span style="white-space: pre-wrap;">  </span>ScriptError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>LoadError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>NotImplementedError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>SyntaxError  
<span style="white-space: pre-wrap;">  </span>SignalException  
<span style="white-space: pre-wrap;">  </span>StandardError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>ArgumentError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>IOError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>EOFError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>IndexError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>LocalJumpError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>NameError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>RangeError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>RegexpError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>RuntimeError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>SecurityError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>SocketError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>SystemCallError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>Errno::\*  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>SystemStackError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>ThreadError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>TypeError  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>ZeroDivisionError  
<span style="white-space: pre-wrap;">  </span>SystemExit  
<span style="white-space: pre-wrap;">  </span>fatal

<span id="raise-exc"></span>[raise exception](#raise-exc-note)  
<span style="white-space: pre-wrap;"> </span>

throw new Error("bad arg");

raise Exception('bad arg')

throw new Exception("bad arg");

<span style="color: gray">\# raises RuntimeError</span>  
raise "bad arg"

<span id="catch-all-handler"></span>[catch-all
handler](#catch-all-handler-note)  
<span style="white-space: pre-wrap;"> </span>

try {  
<span style="white-space: pre-wrap;">  </span>risky();  
} catch (e)
{  
<span style="white-space: pre-wrap;">  </span>console.log(  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>'risky
failed: ' + e.message);  
}

try:  
<span style="white-space: pre-wrap;">  </span>risky()  
except:  
<span style="white-space: pre-wrap;">  </span>print('risky failed')

try {  
<span style="white-space: pre-wrap;">  </span>risky();  
} catch (Exception $e) {  
<span style="white-space: pre-wrap;">  </span>echo "risky failed:
",  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>$e-\>getMessage(),
"\\n";  
}

<span style="color: gray">\# catches StandardError</span>  
begin  
<span style="white-space: pre-wrap;">  </span>risky  
rescue  
<span style="white-space: pre-wrap;">  </span>print "risky failed: "  
<span style="white-space: pre-wrap;">  </span>puts $\!.message  
end

<span id="re-raise-exc"></span>[re-raise exception](#re-raise-exc-note)

try {  
<span style="white-space: pre-wrap;">  </span>throw new
Error("bam\!");  
} catch (e)
{  
<span style="white-space: pre-wrap;">  </span>console.log('re-raising<span style="white-space: pre-wrap;">...</span>');  
<span style="white-space: pre-wrap;">  </span>throw e;  
}

try:  
<span style="white-space: pre-wrap;">  </span>raise
Exception('bam\!')  
except:  
<span style="white-space: pre-wrap;">  </span>print('re-raising<span style="white-space: pre-wrap;">...</span>')  
<span style="white-space: pre-wrap;">  </span>raise

begin  
<span style="white-space: pre-wrap;">  </span>raise "bam\!"  
rescue  
<span style="white-space: pre-wrap;">  </span>puts "re-raising…"  
<span style="white-space: pre-wrap;">  </span>raise  
end  
  
<span style="color: gray">\# if rescue clause raises different
exception,  
\# original exception preserved at e.cause</span>

<span id="last-exc-global"></span>[global variable for last
exception](#last-exc-global-note)

<span style="color: gray">*none*</span>

<span style="color: gray">*last exception:* sys.exc\_info()\[1\]</span>

<span style="color: gray">*none*</span>

<span style="color: gray">*last exception:* $\!</span>  
<span style="color: gray">*backtrace array of exc.:* $@</span>  
<span style="color: gray">*exit status of child:* $?</span>

<span id="def-exc"></span>[define exception](#def-exc-note)

function Bam(msg) {  
<span style="white-space: pre-wrap;">  </span>this.message = msg;  
}  
  
Bam.prototype = new Error;

class Bam(Exception):  
<span style="white-space: pre-wrap;">  </span>def
<span style="white-space: pre-wrap;">\_\_init\_\_</span>(self):  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>super(Bam,
self).<span style="white-space: pre-wrap;">\_\_init\_\_</span>('bam\!')

class Bam extends Exception  
{  
<span style="white-space: pre-wrap;">  </span>function
<span style="white-space: pre-wrap;">\_\_</span>construct()  
<span style="white-space: pre-wrap;">  </span>{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>parent::<span style="white-space: pre-wrap;">\_\_</span>construct("bam\!");  
<span style="white-space: pre-wrap;">  </span>}  
}

class Bam \< Exception  
<span style="white-space: pre-wrap;">  </span>def
initialize  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>super("bam\!")  
<span style="white-space: pre-wrap;">  </span>end  
end

<span id="handle-exc"></span>[handle exception](#handle-exc-note)

try {  
<span style="white-space: pre-wrap;">  </span>throw new Bam("bam\!");  
} catch (e) {  
<span style="white-space: pre-wrap;">  </span>if (e instanceof Bam)
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>console.log(e.message);  
<span style="white-space: pre-wrap;">  </span>}  
<span style="white-space: pre-wrap;">  </span>else
{  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>throw
e;  
<span style="white-space: pre-wrap;">  </span>}  
}

try:  
<span style="white-space: pre-wrap;">  </span>raise Bam()  
except Bam as e:  
<span style="white-space: pre-wrap;">  </span>print(e)

try {  
<span style="white-space: pre-wrap;">  </span>throw new Bam;  
} catch (Bam $e) {  
<span style="white-space: pre-wrap;">  </span>echo $e-\>getMessage(),
"\\n";  
}

begin  
<span style="white-space: pre-wrap;">  </span>raise Bam.new  
rescue Bam =\> e  
<span style="white-space: pre-wrap;">  </span>puts e.message  
end

<span id="finally-block"></span>[finally block](#finally-block-note)  
<span style="white-space: pre-wrap;"> </span>

acquireResource();  
try {  
<span style="white-space: pre-wrap;">  </span>risky();  
} finally {  
<span style="white-space: pre-wrap;">  </span>releaseResource();  
}

acquire\_resource()  
try:  
<span style="white-space: pre-wrap;">  </span>risky()  
finally:  
<span style="white-space: pre-wrap;">  </span>release\_resource()

<span style="color: gray">*PHP 5.5:*</span>  
acquire\_resource();  
try {  
<span style="white-space: pre-wrap;">  </span>risky();  
}  
finally {  
<span style="white-space: pre-wrap;">  </span>release\_resource();  
}

acquire\_resource  
begin  
<span style="white-space: pre-wrap;">  </span>risky  
ensure  
<span style="white-space: pre-wrap;">  </span>release\_resource  
end

<span id="threads"></span>[threads](#threads-note)

node.js

python

php

ruby

<span id="start-thread"></span>[start thread](#start-thread-note)  
<span style="white-space: pre-wrap;"> </span>

class sleep10(threading.Thread):  
<span style="white-space: pre-wrap;">  </span>def
run(self):  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>time.sleep(10)  
  
thr = sleep10()  
thr.start()

thr = Thread.new { sleep 10 }

<span id="wait-on-thread"></span>[wait on
thread](#wait-on-thread-note)  
<span style="white-space: pre-wrap;"> </span>

thr.join()

thr.join

<span id="sleep"></span>[sleep](#sleep-note)

import time  
  
time.sleep(0.5)

<span style="color: gray">\# a float argument will be truncated  
\# to an integer:</span>  
sleep(1);

sleep(0.5)

<span id="timeout"></span>[timeout](#timeout-note)

import signal, time  
  
class Timeout(Exception): pass  
  
def timeout\_handler(signo, fm):  
<span style="white-space: pre-wrap;">  </span>raise Timeout()  
  
signal.signal(signal.SIGALRM,  
<span style="white-space: pre-wrap;">  </span>timeout\_handler)  
  
try:  
<span style="white-space: pre-wrap;">  </span>signal.alarm(5)  
<span style="white-space: pre-wrap;">  </span>might\_take\_too\_long()  
except Timeout:  
<span style="white-space: pre-wrap;">  </span>pass  
signal.alarm(0)

<span style="color: gray">*use* set\_time\_limit *to limit execution
time of the entire script; use* stream\_set\_timeout *to limit time
spent reading from a stream opened with* fopen *or* fsockopen</span>

require 'timeout'  
  
begin  
<span style="white-space: pre-wrap;">  </span>Timeout.timeout(5)
do  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>might\_take\_too\_long  
<span style="white-space: pre-wrap;">  </span>end  
rescue
Timeout::Error  
end

<span style="color: #efefef"><span style="white-space: pre-wrap;">\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_</span></span>

<span style="color: #efefef"><span style="white-space: pre-wrap;">\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_</span></span>

<span style="color: #efefef"><span style="white-space: pre-wrap;">\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_</span></span>

<span style="color: #efefef"><span style="white-space: pre-wrap;">\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_</span></span>

**[sheet two](/scripting2):** [streams](/scripting2#streams) |
[asynchronous events](/scripting2#async) | [files](/scripting2#file) |
[directories](/scripting2#directories) | [processes and
environment](/scripting2#processes-environment) | [option
parsing](/scripting2#option-parsing) | [libraries and
namespaces](/scripting2#libraries-namespaces) |
[objects](/scripting2#objects) | [inheritance and
polymorphism](/scripting2#inheritance-polymorphism) |
[reflection](/scripting2#reflection) | [net and
web](/scripting2#net-web) | [gui](/scripting2#gui) |
[databases](/scripting2#databases) | [unit
tests](/scripting2#unit-tests) |
[logging](/scripting2#logging-profiling) |
[debugging](/scripting2#debugging-profiling)

<span id="version-note"></span>

# <span>[Version](#version)</span>

<span id="version-used-note"></span>

## <span>[version used](#version-used)</span>

The versions used for testing code in the reference sheet.

<span id="version-note"></span>

## <span>[show version](#version)</span>

How to get the version.

**php:**

The function `phpversion()` will return the version number as a string.

**python:**

The following function will return the version number as a string:

<div class="code">

    import platform
    
    platform.python_version()

</div>

**ruby:**

Also available in the global constant `RUBY_VERSION`.

<span id="implicit-prologue-note"></span>

## <span>[implicit prologue](#implicit-prologue)</span>

Code which examples in the sheet assume to have already been executed.

**javascript:**

`underscore.js` adds some convenience functions as attributes of an
object which is normally stored in the underscore `_` variable. E.g.:

<div class="code">

    _.map([1, 2, 3], function(n){ return n * n; });

</div>

[cdnjs](http://cdnjs.com/libraries/underscore.js) hosts underscore.js
and other JavaScript libraries for situations where it is inconvenient
to have the webserver host the libraries.

When using `underscore.js` with the Node REPL, there is a conflict,
since the Node REPL uses the underscore `_` variable to store the result
of the last evaluation.

<div class="code">

    $ npm install underscore
    
    $ node
    
    > var us = require('underscore'); _
    
    > us.keys({"one": 1, "two": 2});
    [ 'one', 'two' ]

</div>

**php:**

The `mbstring` package adds UTF-8 aware string functions with `mb_`
prefixes.

**python:**

We assume that `os`, `re`, and `sys` are always imported.

<span id="grammar-execution-note"></span>

# <span>[Grammar and Execution](#grammar-execution)</span>

<span id="interpreter-note"></span>

## <span>[interpreter](#interpreter)</span>

The customary name of the interpreter and how to invoke it.

**php:**

`php -f` will only execute portions of the source file within a \<?php
<span style="color: gray">*php code*</span> ?\> tag as php code.
Portions of the source file outside of such tags is not treated as
executable code and is echoed to standard out.

If short tags are enabled, then php code can also be placed inside \<?
<span style="color: gray">*php code*</span> ?\> and \<?=
<span style="color: gray">*php code*</span> ?\> tags.

\<?= <span style="color: gray">*php code*</span> ?\> is identical to
\<?php echo <span style="color: gray">*php code*</span> ?\>.

<span id="repl-note"></span>

## <span>[repl](#repl)</span>

The customary name of the repl.

**php:**

The `php -a` REPL does not save or display the result of an expression.

**python:**

The python repl saves the result of the last statement in
<span style="white-space: pre-wrap;">\_</span>.

**ruby:**

`irb` saves the result of the last statement in
<span style="white-space: pre-wrap;">\_</span>.

<span id="cmd-line-program-note"></span>

## <span>[command line program](#cmd-line-program)</span>

How to pass the code to be executed to the interpreter as a command line
argument.

<span id="block-delimiters-note"></span>

## <span>[block delimiters](#block-delimiters)</span>

How blocks are delimited.

**python:**

Python blocks begin with a line that ends in a colon. The block ends
with the first line that is not indented further than the initial line.
Python raises an IndentationError if the statements in the block that
are not in a nested block are not all indented the same. Using tabs in
Python source code is unrecommended and many editors replace them
automatically with spaces. If the Python interpreter encounters a tab,
it is treated as 8 spaces.

The python repl switches from a `>>>` prompt to a … prompt inside a
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

<span id="statement-separator-note"></span>

## <span>[statement separator](#statement-separator)</span>

How the parser determines the end of a statement.

**php:**

Inside braces statements must be terminated by a semicolon. The
following causes a parse error:

<div class="code">

    <? if (true) { echo "true" } ?>

</div>

The last statement inside `<?= ?>` or `<? ?>` tags does not need to be
semicolon terminated, however. The following code is legal:

<div class="code">

    <?= $a = 1 ?>
    <? echo $a ?>

</div>

**python:**

Newline does not terminate a statement when:

  - inside parens
  - inside list \[\] or dictionary {} literals

Python single quote '' and double quote "" strings cannot contain
newlines except as the two character escaped form \\n. Putting a newline
in these strings results in a syntax error. There is however a
multi-line string literal which starts and ends with three single quotes
''' or three double quotes: """.

A newline that would normally terminate a statement can be escaped with
a backslash.

**ruby:**

Newline does not terminate a statement when:

  - inside single quotes '', double quotes "", backticks \`\`, or parens
    ()
  - after an operator such as + or , that expects another argument

Ruby permits newlines in array \[\] or hash literals, but only after a
comma , or associator =\>. Putting a newline before the comma or
associator results in a syntax error.

A newline that would normally terminate a statement can be escaped with
a backslash.

<span id="source-code-encoding-note"></span>

## <span>[source code encoding](#source-code-encoding)</span>

How to identify the character encoding for a source code file.

Setting the source code encoding makes it possible to safely use
non-ASCII characters in string literals and regular expression literals.

<span id="eol-comment-note"></span>

## <span>[end-of-line comment](#eol-comment)</span>

How to create a comment that ends at the next newline.

<span id="multiple-line-comment-note"></span>

## <span>[multiple line comment](#multiple-line-comment)</span>

How to comment out multiple lines.

**python:**

The triple single quote ''' and triple double quote """ syntax is a
syntax for string literals.

<span id="var-expr-note"></span>

# <span>[Variables and Expressions](#var-expr)</span>

<span id="local-var-note"></span>

## <span>[local variable](#local-var)</span>

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
dollar sign ($) or ampersand (@) as its first character then its scope
is scope defining region which most immediately contains it.

A lower case name can refer to a local variable or method. If both are
defined, the local variable takes precedence. To invoke the method make
the receiver explicit: e.g. self.*name*. However, outside of class and
modules local variables hide functions because functions are private
methods in the class *Object*. Assignment to *name* will create a local
variable if one with that name does not exist, even if there is a method
*name*.

<span id="file-scope-var-note"></span>

## <span>[file scope variable](#file-scope-var)</span>

How to define a variable with scope bound by the source file.

<span id="global-var-note"></span>

## <span>[global variable](#global-var)</span>

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

A variable is global if it starts with a dollar sign: $.

<span id="const-note"></span>

## <span>[constant](#const)</span>

How to declare a constant.

**php:**

A constant can be declared inside a class:

<div class="code">

    class Math {
      const pi = 3.14;
    }

</div>

Refer to a class constant like this:

<div class="code">

    Math::pi

</div>

**ruby:**

Capitalized variables contain constants and class/module names. By
convention, constants are all caps and class/module names are camel
case. The ruby interpreter does not prevent modification of constants,
it only gives a warning. Capitalized variables are globally visible, but
a full or relative namespace name must be used to reach them: e.g.
Math::PI.

<span id="assignment-note"></span>

## <span>[assignment](#assignment)</span>

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

<div class="code">

    a = b = 3

</div>

**ruby:**

Assignment operators have right precedence and evaluate to the right
argument, so they can be chained. If the variable on the left does not
exist, then it is created.

<span id="parallel-assignment-note"></span>

## <span>[parallel assignment](#parallel-assignment)</span>

How to assign values to variables in parallel.

**python:**

The r-value can be a list or tuple:

<div class="code">

    nums = [1, 2, 3]
    a, b, c = nums
    more_nums = (6, 7, 8)
    d, e, f = more_nums

</div>

Nested sequences of expression can be assigned to a nested sequences of
l-values, provided the nesting matches. This assignment will set a to 1,
b to 2, and c to 3:

<div class="code">

    (a,[b,c]) = [1,(2,3)]

</div>

This assignment will raise a `TypeError`:

<div class="code">

    (a,(b,c)) = ((1,2),3)

</div>

In Python 3 the splat operator `*` can be used to collect the remaining
right side elements in a list:

<div class="code">

    x, y, *z = 1, 2        # assigns [] to z
    x, y, *z = 1, 2, 3     # assigns [3] to z
    x, y, *z = 1, 2, 3, 4  # assigns [3, 4] to z

</div>

**ruby:**

The r-value can be an array:

<div class="code">

    nums = [1, 2, 3]
    a,b,c = nums

</div>

<span id="swap-note"></span>

## <span>[swap](#swap)</span>

How to swap the values held by two variables.

<span id="compound-assignment-note"></span>

## <span>[compound assignment](#compound-assignment)</span>

Compound assignment operators mutate a variable, setting it to the value
of an operation which takes the previous value of the variable as an
argument.

If `<OP>` is a binary operator and the language has the compound
assignment operator `<OP>=`, then the following are equivalent:

<div class="code">

    x <OP>= y
    x = x <OP> y

</div>

The compound assignment operators are displayed in this order:

*First row:* arithmetic operator assignment: addition, subtraction,
multiplication, (float) division, integer division, modulus, and
exponentiation.  
*Second row:* string concatenation assignment and string replication
assignment  
*Third row:* logical operator assignment: and, or, xor  
*Fourth row:* bit operator assignment: left shift, right shift, and, or,
xor.

**python:**

Python compound assignment operators do not return a value and hence
cannot be used in expressions.

<span id="incr-decr-note"></span>

## <span>[increment and decrement](#incr-decr)</span>

The C-style increment and decrement operators can be used to increment
or decrement values. They return values and thus can be used in
expressions. The prefix versions return the value in the variable after
mutation, and the postfix version return the value before mutation.

Incrementing a value two or more times in an expression makes the order
of evaluation significant:

<div class="code">

    x = 1;
    foo(++x, ++x); // foo(2, 3) or foo(3, 2)?
    
    x = 1;
    y = ++x/++x;  // y = 2/3 or y = 3/2?

</div>

Python avoids the problem by not having an in-expression increment or
decrement.

Ruby mostly avoids the problem by providing a non-mutating increment and
decrement. However, here is a Ruby expression which is dependent on
order of evaluation:

<div class="code">

    x = 1
    y = (x += 1)/(x += 1)

</div>

**php:**

The increment and decrement operators also work on strings. There are
postfix versions of these operators which evaluate to the value before
mutation:

<div class="code">

    $x = 1;
    $x++;
    $x--;

</div>

**ruby:**

The Integer class defines `succ`, `pred`, and `next`, which is a synonym
for `succ`.

The String class defines `succ`, `succ!`, `next`, and `next!`. `succ!`
and `next!` mutate the string.

<span id="null-note"></span>

## <span>[null](#null)</span>

The null literal.

<span id="null-test-note"></span>

## <span>[null test](#null-test)</span>

How to test if a variable contains null.

**php:**

*$v == NULL* does not imply that *$v* is *NULL*, since any comparison
between *NULL* and a falsehood will return true. In particular, the
following comparisons are true:

<div class="code">

    $v = NULL;
    if ($v == NULL) { echo "true"; }
    
    $v = 0;
    if ($v == NULL) { echo "sadly true"; }
    
    $v = '';
    if ($v == NULL) { echo "sadly true"; }

</div>

<span id="undef-var-note"></span>

## <span>[undefined variable](#undef-var)</span>

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

<div class="code">

    not_defined = False
    try: v
    except NameError:
      not_defined = True

</div>

**ruby:**

How to test if a variable is defined:

<div class="code">

    ! defined?(v)

</div>

<span id="conditional-expr-note"></span>

## <span>[conditional expression](#conditional-expr)</span>

How to write a conditional expression. A ternary operator is an operator
which takes three arguments. Since

<span style="color: gray">*condition*</span> ?
<span style="color: gray">*true value*</span> :
<span style="color: gray">*false value*</span>

is the only ternary operator in C, it is unambiguous to refer to it as
*the* ternary operator.

**python:**

The Python conditional expression comes from Algol.

**ruby:**

The Ruby `if` statement is also an expression:

<div class="code">

    x = if x > 0
      x
    else
      -x
    end

</div>

<span id="arithmetic-logic-note"></span>

# <span>[Arithmetic and Logic](#arithmetic-logic)</span>

<span id="true-false-note"></span>

## <span>[true and false](#true-false)</span>

Literals for the booleans.

These are the return values of the relational operators.

**php:**

Any identifier which matches TRUE case-insensitive can be used for the
TRUE boolean. Similarly for FALSE.

In general, PHP variable names are case-sensitive, but function names
are case-insensitive.

When converted to a string for display purposes, TRUE renders as "1" and
FALSE as "". The equality tests `TRUE == 1` and `FALSE == ""` evaluate
as TRUE but the equality tests `TRUE === 1` and `FALSE === ""` evaluate
as FALSE.

<span id="falsehoods-note"></span>

## <span>[falsehoods](#falsehoods)</span>

Values which behave like the false boolean in a conditional context.

Examples of conditional contexts are the conditional clause of an `if`
statement and the test of a `while` loop.

**python:**

Whether a object evaluates to True or False in a boolean context can be
customized by implementing a
<span style="white-space: pre-wrap;">\_\_nonzero\_\_</span> (Python 2)
or <span style="white-space: pre-wrap;">\_\_bool\_\_</span> (Python 3)
instance method for the class.

<span id="logical-op-note"></span>

## <span>[logical operators](#logical-op)</span>

Logical and, or, and not.

**php, ruby:**

&& and <span style="white-space: pre-wrap;">||</span> have higher
precedence than assignment, compound assignment, and the ternary
operator (?:), which have higher precedence than *and* and *or*.

<span id="relational-op-note"></span>

## <span>[relational operators](#relational-op)</span>

Equality, inequality, greater than, less than, greater than or equal,
less than or equal.

**php:**

Most of the relational operators will convert a string to a number if
the other operand is a number. Thus 0 == "0" is true. The operators ===
and \!== do not perform this conversion, so 0 === "0" is false.

**python:**

Relational operators can be chained. The following expressions evaluate
to true:

<div class="code">

    1 < 2 < 3
    1 == 1 != 2

</div>

In general if *A<sub>i</sub>* are expressions and *op<sub>i</sub>* are
relational operators,
then

<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>`A1
op1 A2 op2 A3 … An opn An+1`

is true if and only if each of the following is
true

<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>`A1
op1
A2`  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>`A2
op2
A3`  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>…  
<span style="white-space: pre-wrap;">  </span><span style="white-space: pre-wrap;">  </span>`An
opn An+1`

<span id="min-max-note"></span>

## <span>[min and max](#min-max)</span>

How to get the min and max.

<span id="arith-op-note"></span>

## <span>[arithmetic operators](#arith-op)</span>

The operators for addition, subtraction, multiplication, float division,
integer division, modulus, and exponentiation.

<span id="int-div-note"></span>

## <span>[integer division](#int-div)</span>

How to get the integer quotient of two integers.

<span id="divmod-note"></span>

## <span>[divmod](#divmod)</span>

How to get the quotient and remainder with single function call.

<span id="int-div-zero-note"></span>

## <span>[integer division by zero](#int-div-zero)</span>

What happens when an integer is divided by zero.

<span id="float-div-note"></span>

## <span>[float division](#float-div)</span>

How to perform floating point division, even if the operands might be
integers.

<span id="float-div-zero-note"></span>

## <span>[float division by zero](#float-div-zero)</span>

What happens when a float is divided by zero.

<span id="power-note"></span>

## <span>[power](#power)</span>

How to get the value of a number raised to a power.

<span id="sqrt-note"></span>

## <span>[sqrt](#sqrt)</span>

The square root function.

<span id="sqrt-negative-one-note"></span>

## <span>[sqrt -1](#sqrt-negative-one)</span>

The result of taking the square root of negative one.

<span id="transcendental-func-note"></span>

## <span>[transcendental functions](#transcendental-func)</span>

Some mathematical functions. Trigonometric functions are in radians
unless otherwise noted. Logarithms are natural unless otherwise noted.

**python:**

Python also has *math.log10*. To compute the log of *x* for base *b*,
use:

<div class="code">

    math.log(x)/math.log(b)

</div>

**ruby:**

Ruby also has *Math.log2*, *Math.log10*. To compute the log of *x* for
base *b*, use

<div class="code">

    Math.log(x)/Math.log(b)

</div>

<span id="transcendental-const-note"></span>

## <span>[transcendental constants](#transcendental-const)</span>

Constants for π and Euler's constant.

<span id="float-truncation-note"></span>

## <span>[float truncation](#float-truncation)</span>

How to truncate a float to the nearest integer towards zero; how to
round a float to the nearest integer; how to find the nearest integer
above a float; how to find the nearest integer below a float; how to
take the absolute value.

<span id="abs-val-note"></span>

## <span>[absolute value](#abs-val)</span>

How to get the absolute value of a number.

<span id="int-overflow-note"></span>

## <span>[integer overflow](#int-overflow)</span>

What happens when the largest representable integer is exceeded.

<span id="float-overflow-note"></span>

## <span>[float overflow](#float-overflow)</span>

What happens when the largest representable float is exceeded.

<span id="rational-note"></span>

## <span>[rational numbers](#rational)</span>

How to create rational numbers and get the numerator and denominator.

**ruby:**

Require the library *mathn* and integer division will yield rationals
instead of truncated integers.

<span id="complex-note"></span>

## <span>[complex numbers](#complex)</span>

**python:**

Most of the functions in *math* have analogues in *cmath* which will
work correctly on complex numbers.

<span id="random-note"></span>

## <span>[random integer, uniform float, normal float](#random)</span>

How to generate a random integer between 0 and 99, include, float
between zero and one in a uniform distribution, or a float in a normal
distribution with mean zero and standard deviation one.

<span id="random-seed-note"></span>

## <span>[set random seed, get and restore seed](#random-seed)</span>

How to set the random seed; how to get the current random seed and later
restore it.

All the languages in the sheet set the seed automatically to a value
that is difficult to predict. The Ruby MRI interpreter uses the current
time and process ID, for example. As a result there is usually no need
to set the seed.

Setting the seed to a hardcoded value yields a random but repeatable
sequence of numbers. This can be used to ensure that unit tests which
cover code using random numbers doesn't intermittently fail.

The seed is global state. If multiple functions are generating random
numbers then saving and restoring the seed may be necessary to produce a
repeatable sequence.

<span id="bit-op-note"></span>

## <span>[bit operators](#bit-op)</span>

The bit operators for left shift, right shift, and, inclusive or,
exclusive or, and
negation.

<span id="binary-octal-hex-literals-note"></span>

## <span>[binary, octal, and hex literals](#binary-octal-hex-literals)</span>

Binary, octal, and hex integer literals

<span id="radix-note"></span>

## <span>[radix](#radix)</span>

How to convert integers to strings of digits of a given base. How to
convert such strings into integers.

**python**

Python has the functions `bin`, `oct`, and `hex` which take an integer
and return a string encoding the integer in base 2, 8, and 16.

<div class="code">

    bin(42)
    oct(42)
    hex(42)

</div>

<span id="strings-note"></span>

# <span>[Strings](#strings)</span>

<span id="str-type-note"></span>

## <span>[string type](#str-type)</span>

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

<span id="str-literal-note"></span>

## <span>[string literal](#str-literal)</span>

The syntax for string literals.

**python:**

String literals may have a `u` prefix

<div class="code">

    u'lorem ipsum'
    u"lorem ipsum"
    u'''lorem
    ipsum'''
    u"""lorem
    ipsum"""

</div>

In Python 3, these are identical to literals without the `u` prefix.

In Python 2, these create `unicode` strings instead of `str` strings.
Since the Python 2 `unicode` type corresponds to the Python 3 `str`
type, portable code will use the `u` prefix.

**ruby:**

How to specify custom delimiters for single and double quoted strings.
These can be used to avoid backslash escaping. If the left delimiter is
(, \[, or { the right delimiter must be ), \], or }, respectively.

<div class="code">

    s1 = %q(lorem ipsum)
    s2 = %Q(#{s1} dolor sit amet)

</div>

<span id="newline-in-str-literal-note"></span>

## <span>[newline in literal](#newline-in-str-literal)</span>

Whether newlines are permitted in string literals.

**python:**

Newlines are not permitted in single quote and double quote string
literals. A string can continue onto the following line if the last
character on the line is a backslash. In this case, neither the
backslash nor the newline are taken to be part of the string.

Triple quote literals, which are string literals terminated by three
single quotes or three double quotes, can contain newlines:

<div class="code">

    '''This is
    two lines'''
    
    """This is also
    two lines"""

</div>

<span id="str-literal-esc-note"></span>

## <span>[literal escapes](#str-literal-esc)</span>

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

<div class="code">

    r'C:\Documents and Settings\Admin'
    r"C:\Windows\System32"

</div>

The \\u<span style="color: gray">*hhhh*</span> escapes are also
available inside Python 2 Unicode literals. Unicode literals have a *u*
prefiix:

<div class="code">

    u'lambda: \u03bb'

</div>

This syntax is also available in Python 3.3, but not Python 3.2. In
Python 3.3 it creates a string of type `str` which has the same features
as the `unicode` type of Python 2.7.

<span id="here-doc-note"></span>

## <span>[here document](#here-doc)</span>

Here documents are strings terminated by a custom identifier. They
perform variable substitution and honor the same backslash escapes as
double quoted strings.

**python:**

Triple quotes honor the same backslash escape sequences as regular
quotes, so triple quotes can otherwise be used like here documents:

<div class="code">

    s = '''here document
    there computer
    '''

</div>

**ruby:**

Put the customer identifier in single quotes to prevent variable
interpolation and backslash escape interpretation:

<div class="code">

    s = <<'EOF'
    Ruby code uses #{var} type syntax
    to interpolate variables into strings.
    EOF

</div>

<span id="var-interpolation-note"></span>

## <span>[variable interpolation](#var-interpolation)</span>

How to interpolate variables into strings.

**python:**

The f'1 + 1 = {1 + 1}' and f"1 + 1 = {1 + 1}" literals, which support
variable interpolation and expression interpolation, are new in Python
3.6.

`str.format` will take named or positional parameters. When used with
named parameters `str.format` can mimic the variable interpolation
feature of the other languages.

A selection of variables in scope can be passed explicitly:

<div class="code">

    count = 3
    item = 'ball'
    print('{count} {item}s'.format(
      count=count,
      item=item))

</div>

Python 3 has `format_map` which accepts a `dict` as an argument:

<div class="code">

    count = 3
    item = 'ball'
    print('{count} {item}s'.format_map(locals()))

</div>

<span id="expr-interpolation-note"></span>

## <span>[expression interpolation](#expr-interpolation)</span>

How to interpolate the result of evaluating an expression into a string.

<span id="format-str-note"></span>

## <span>[format string](#format-str)</span>

How to create a string using a printf style format.

**python:**

The % operator will interpolate arguments into printf-style format
strings.

The `str.format` with positional parameters provides an alternative
format using curly braces {0}, {1}, … for replacement fields.

The curly braces are escaped by doubling:

<div class="code">

    'to insert parameter {0} into a format, use {{{0}}}'.format(3)

</div>

If the replacement fields appear in sequential order and aren't
repeated, the numbers can be omitted:

<div class="code">

    'lorem {} {} {}'.format('ipsum', 13, 3.7)

</div>

<span id="mutable-str-note"></span>

## <span>[are strings mutable?](#mutable-str)</span>

Are strings mutable?

<span id="copy-str-note"></span>

## <span>[copy string](#copy-str)</span>

How to copy a string such that changes to the original do not modify the
copy.

<span id="str-concat-note"></span>

## <span>[concatenate](#str-concat)</span>

The string concatenation operator.

<span id="str-replicate-note"></span>

## <span>[replicate](#str-replicate)</span>

The string replication operator.

<span id="translate-case-note"></span>

## <span>[translate case](#translate-case)</span>

How to put a string into all caps or all lower case letters.

<span id="capitalize-note"></span>

## <span>[capitalize](#capitalize)</span>

How to capitalize a string and the words in a string.

The examples lowercase non-initial letters.

**php:**

How to define a UTF-8 aware version of `ucfirst`. This version also puts
the rest of the string in lowercase:

<div class="code">

    function mb_ucfirst($string, $encoding = "UTF-8")
    {
        $strlen = mb_strlen($string, $encoding);
        $firstChar = mb_substr($string, 0, 1, $encoding);
        $then = mb_substr(mb_strtolower($string), 1, $strlen - 1, $encoding);
        return mb_strtoupper($firstChar, $encoding) . $then;
    }

</div>

**ruby:**

Rails monkey patches the `String` class with the `titleize` method for
capitalizing the words in a string.

<span id="trim-note"></span>

## <span>[trim](#trim)</span>

How to remove whitespace from the ends of a string.

<span id="pad-note"></span>

## <span>[pad](#pad)</span>

How to pad the edge of a string with spaces so that it is a prescribed
length.

<span id="num-to-str-note"></span>

## <span>[number to string](#num-to-str)</span>

How to convert numeric data to string data.

<span id="fmt-float-note"></span>

## <span>[format float](#fmt-float)</span>

How to control the number of digits in a float when converting it to a
string.

**python:**

The number after the decimal controls the number of digits after the
decimal:

<div class="code">

    >>> '%.2f' % math.pi
    '3.14'

</div>

The number after the decimal controls the total number of digits:

<div class="code">

    >>> '{:.3}'.format(math.pi)
    '3.14'

</div>

<span id="str-to-num-note"></span>

## <span>[string to number](#str-to-num)</span>

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

<span id="str-join-note"></span>

## <span>[string join](#str-join)</span>

How to concatenate the elements of an array into a string with a
separator.

<span id="split-note"></span>

## <span>[split](#split)</span>

How to split a string containing a separator into an array of
substrings.

See also [scan](#scan).

**python:**

`str.split()` takes simple strings as delimiters; use `re.split()` to
split on a regular expression:

<div class="code">

    re.split('\s+', 'do re mi fa')
    re.split('\s+', 'do re mi fa', 1)

</div>

<span id="split-in-two-note"></span>

## <span>[split in two](#split-in-two)</span>

How to split a string in two.

**javascript:**

A regular expression is probably the best method for splitting a string
in two:

<div class="code">

    var m = /^([^ ]+) (.+)/.exec("do re mi");
    var first = m[1];
    var rest = m[2];

</div>

This technique works when the delimiter is a fixed string:

<div class="code">

    var a = "do re mi".split(" ");
    var first = a[0];
    var rest = a.splice(1).join(" ");

</div>

**python:**

Methods for splitting a string into three parts using the first or last
occurrence of a substring:

<div class="code">

    'do re mi'.partition(' ')         # returns ('do', ' ', 're mi')
    'do re mi'.rpartition(' ')        # returns ('do re', ' ', 'mi')

</div>

<span id="split-keep-delimiters-note"></span>

## <span>[split and keep delimiters](#split-keep-delimiters)</span>

How to split a string with the delimiters preserved as separate
elements.

<span id="prefix-suffix-test-note"></span>

## <span>[prefix and suffix test](#prefix-suffix-test)</span>

How to test whether a string begins or ends with a substring.

<span id="str-len-note"></span>

## <span>[length](#str-len)</span>

How to get the length in characters of a string.

<span id="index-substr-note"></span>

## <span>[index of substring](#index-substr)</span>

How to find the index of the leftmost occurrence of a substring in a
string; how to find the index of the rightmost occurrence.

<span id="extract-substr-note"></span>

## <span>[extract substring](#extract-substr)</span>

How to extract a substring from a string by index.

<span id="bytes-type-note"></span>

## <span>[byte array type](#bytes-type)</span>

The type for an array of bytes.

<span id="bytes-to-str-note"></span>

## <span>[byte array to string](#bytes-to-str)</span>

How to convert an array of bytes to a string of Unicode characters.

<span id="str-to-bytes-note"></span>

## <span>[string to byte array](#str-to-bytes)</span>

How to convert a string of Unicode characters to an array of bytes.

<span id="lookup-char-note"></span>

## <span>[character lookup](#lookup-char)</span>

How to look up the character in a string at an index.

<span id="chr-ord-note"></span>

## <span>[chr and ord](#chr-ord)</span>

Converting characters to ASCII codes and back.

The languages in this reference sheet do not have character literals, so
characters are represented by strings of length one.

<span id="str-to-char-array-note"></span>

## <span>[to array of characters](#str-to-char-array)</span>

How to split a string into an array of single character strings.

<span id="translate-char-note"></span>

## <span>[translate characters](#translate-char)</span>

How to apply a character mapping to a string.

**python:**

In Python 2, the string of lowercase letters is in `string.lowercase`
instead of `string.ascii_lowercase`.

In Python 2, the `maketrans` function is in the module `string` instead
of `str`.

<span id="delete-char-note"></span>

## <span>[delete characters](#delete-char)</span>

How to remove all specified characters from a string; how to remove all
but the specified characters from a string.

<span id="squeeze-char-note"></span>

## <span>[squeeze characters](#squeeze-char)</span>

How to replace multiple adjacent occurrences of a character with a
single occurrence.

<span id="regexes-note"></span>

# <span>[Regular Expressions](#regexes)</span>

  - [PHP PCRE Regexes](http://php.net/manual/en/book.pcre.php)
  - Python re library: [2.7](http://docs.python.org/library/re.html),
    [3.1](http://docs.python.org/release/3.1.3/library/re.html)
  - [Ruby Regexp](http://www.ruby-doc.org/core/classes/Regexp.html)

Regular expressions or regexes are a way of specifying sets of strings.
If a string belongs to the set, the string and regex "match". Regexes
can also be used to parse strings.

The modern notation for regexes was introduced by Unix command line
tools in the 1970s. POSIX standardized the notation into two types:
extended regexes and the more archaic basic regexes. Perl regexes are
extended regexes augmented by new character class abbreviations and a
few other features introduced by the Perl interpreter in the 1990s. All
the languages in this sheet use Perl regexes.

Any string that doesn't contain regex metacharacters is a regex which
matches itself. The regex metacharacters are: `[ ] . | ( ) * + ? { } ^ $
\`

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

<span id="regex-char-class-abbrev"></span>  
**character class abbreviations:**

<table>
<thead>
<tr class="header">
<th>abbrev</th>
<th>name</th>
<th>character class</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>\d</td>
<td>digit</td>
<td>[0-9]</td>
</tr>
<tr class="even">
<td>\D</td>
<td>nondigit</td>
<td>[^0-9]</td>
</tr>
<tr class="odd">
<td>\h</td>
<td><span style="color: gray"><em>PHP:</em></span> horizontal whitespace character<br />
<span style="color: gray"><em>Ruby:</em></span> hex digit</td>
<td><span style="color: gray"><em>PHP:</em></span> [ \t]<br />
<span style="color: gray"><em>Ruby:</em></span> [0-9a-fA-F]</td>
</tr>
<tr class="even">
<td>\H</td>
<td><span style="color: gray"><em>PHP:</em></span> not a horizontal whitespace character<br />
<span style="color: gray"><em>Ruby:</em></span> not a hex digit</td>
<td><span style="color: gray"><em>PHP:</em></span> [^ \t]<br />
<span style="color: gray"><em>Ruby:</em></span> [^0-9a-fA-F]</td>
</tr>
<tr class="odd">
<td>\s</td>
<td>whitespace character</td>
<td>[ \t\r\n\f]</td>
</tr>
<tr class="even">
<td>\S</td>
<td>non whitespace character</td>
<td>[^ \t\r\n\f]</td>
</tr>
<tr class="odd">
<td>\v</td>
<td>vertical whitespace character</td>
<td>[\r\n\f]</td>
</tr>
<tr class="even">
<td>\V</td>
<td>not a vertical whitespace character</td>
<td>[^\r\n\f]</td>
</tr>
<tr class="odd">
<td>\w</td>
<td>word character</td>
<td>[A-Za-z0-9_]</td>
</tr>
<tr class="even">
<td>\W</td>
<td>non word character</td>
<td>[^A-Za-z0-9_]</td>
</tr>
</tbody>
</table>

**alternation and grouping: | ( )**

The vertical pipe | is used for alternation and parens () for grouping.

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
that `^a{4}*$` matches strings with the letter a in multiples of
4.

| quantifier                                     | \# of occurrences of argument matched |
| ---------------------------------------------- | ------------------------------------- |
| <span style="white-space: pre-wrap;">\*</span> | zero or more, greedy                  |
| \+                                             | one or more, greedy                   |
| ?                                              | zero or one, greedy                   |
| {m,n}                                          | *m* to *n*, greedy                    |
| {n}                                            | exactly *n*                           |
| {m,}                                           | *m* or more, greedy                   |
| {,n}                                           | zero to *n*, greedy                   |
| \*?                                            | zero or more, lazy                    |
| \+?                                            | one or more, lazy                     |
| {m,n}?                                         | *m* to *n*, lazy                      |
| {m,}?                                          | *m* or more, lazy                     |
| {,n}?                                          | zero to *n*, lazy                     |

When there is a choice, greedy quantifiers will match the maximum
possible number of occurrences of the argument. Lazy quantifiers match
the minimum possible number.

**anchors: ^
$**

| anchor | matches                                                                                                      |
| ------ | ------------------------------------------------------------------------------------------------------------ |
| ^      | beginning of a string. In Ruby or when *m* modifier is used also matches right side of a newline             |
| $      | end of a string. In Ruby or when *m* modifier is used also matches left side of a newline                    |
| \\A    | beginning of the string                                                                                      |
| \\b    | word boundary. In between a \\w and a \\W character or in between a \\w character and the edge of the string |
| \\B    | not a word boundary. In between two \\w characters or two \\W characters                                     |
| \\z    | end of the string                                                                                            |
| \\Z    | end of the string unless it is a newline, in which case it matches the left side of the terminal newline     |

**escaping: \\**

To match a metacharacter, put a backslash in front of it. To match a
backslash use two backslashes.

**php:**

PHP 5.3 still supports the EREG engine, though the functions which use
it are deprecated. These include the `split` function and functions
which start with `ereg`. The preferred functions are `preg_split` and
the other functions with a `preg` prefix.

<span id="regex-literal-note"></span>

## <span>[literal, custom delimited literal](#regex-literal)</span>

The literal for a regular expression; the literal for a regular
expression with a custom delimiter.

**javascript:**

The constructor for a regular expression is:

<div class="code">

    var rx = RegExp("lorem|ipsum");

</div>

**php:**

PHP regex literals are strings. The first character is the delimiter and
it must also be the last character. If the start delimiter is (, {, or
\[ the end delimiter must be ), }, or \], respectively.

Here are the signatures from the PHP manual for the preg functions used
in this
    sheet:

<div class="code">

    array preg_split ( string $pattern , string $subject [, int $limit = -1 [, int $flags = 0 ]] )
    
    int preg_match ( string $pattern , string $subject [, array &$matches [, int $flags = 0 [, int $offset = 0 ]]] )
    
    mixed preg_replace ( mixed $pattern , mixed $replacement , mixed $subject [, int $limit = -1 [, int &$count ]] )
    
    int preg_match_all ( string $pattern , string $subject [, array &$matches [, int $flags = PREG_PATTERN_ORDER [, int $offset = 0 ]]] )

</div>

**python:**

Python does not have a regex literal, but the `re.compile` function can
be used to create regex objects.

Compiling regexes can always be avoided:

<div class="code">

    re.compile('\d{4}').search('1999')
    re.search('\d{4}', '1999')
    
    re.compile('foo').sub('bar', 'foo bar')
    re.sub('foo', 'bar', 'foo bar')
    
    re.compile('\w+').findall('do re me')
    re.findall('\w+', 'do re me')

</div>

<span id="ascii-char-class-abbrev-note"></span>

## <span>[ascii character class abbreviations](#ascii-char-class-abbrev)</span>

The supported [character class abbreviations](#regex-char-class-abbrev).

Note that `\h` refers to horizontal whitespace (i.e. a space or tab) in
PHP and a hex digit in Ruby. Similarly `\H` refers to something that
isn't horizontal whitespace in PHP and isn't a hex digit in
Ruby.

<span id="unicode-char-class-abbrev-note"></span>

## <span>[unicode character class abbreviations](#unicode-char-class-abbrev)</span>

The supported character class abbreviations for sets of Unicode
characters.

Each Unicode character belongs to one of these major categories:

|   |             |
| - | ----------- |
| C | Other       |
| L | Letter      |
| M | Mark        |
| N | Number      |
| P | Punctuation |
| S | Symbol      |
| Z | Separator   |

Each major category is subdivided into multiple minor categories. Each
minor category has a two letter code, where the first letter is the
major category. For example, `Nd` is "Number, decimal digit".

Download
[UnicodeData.txt](http://www.unicode.org/Public/UNIDATA/UnicodeData.txt)
to find out which major and minor category and character belongs to.

<span id="regex-anchors-note"></span>

## <span>[anchors](#regex-anchors)</span>

The supported anchors.

<span id="regex-test-note"></span>

## <span>[match test](#regex-test)</span>

How to test whether a string matches a regular expression.

**python:**

The `re.match` function returns true only if the regular expression
matches the beginning of the string. `re.search` returns true if the
regular expression matches any substring of the of string.

**ruby:**

`match` is a method of both `Regexp` and `String` so can match with both

<div class="code">

    /1999/.match("1999")

</div>

and

<div class="code">

    "1999".match(/1999/)

</div>

When variables are involved it is safer to invoke the `Regexp` method
because string variables are more likely to contain `nil`.

<span id="case-insensitive-regex-note"></span>

## <span>[case insensitive match test](#case-insensitive-regex)</span>

How to perform a case insensitive match test.

<span id="regex-modifiers-note"></span>

## <span>[modifiers](#regex-modifiers)</span>

Modifiers that can be used to adjust the behavior of a regular
expression.

The lists are not comprehensive. For all languages except Ruby there are
additional modifiers.

<table>
<thead>
<tr class="header">
<th>modifier</th>
<th>behavior</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>e</td>
<td><span style="color: gray"><em>PHP:</em></span> when used with preg_replace, the replacement string, after backreferences are substituted, is eval'ed as PHP code and the result is used as the replacement.</td>
</tr>
<tr class="even">
<td>g</td>
<td><span style="color: gray"><em>JavaScript:</em></span> read all non-overlapping matches into an array.</td>
</tr>
<tr class="odd">
<td>i, re.I</td>
<td><span style="color: gray"><em>all:</em></span> ignores case. Upper case letters match lower case letters and vice versa.</td>
</tr>
<tr class="even">
<td>m, re.M</td>
<td><span style="color: gray"><em>JavaScript, PHP, Python:</em></span> makes the ^ and $ match the right and left edge of newlines in addition to the beginning and end of the string.<br />
<span style="color: gray"><em>Ruby:</em></span> makes the period . match newline characters.</td>
</tr>
<tr class="odd">
<td>o</td>
<td><span style="color: gray"><em>Ruby:</em></span> performs variable interpolation #{ } only once per execution of the program.</td>
</tr>
<tr class="even">
<td>s, re.S</td>
<td><span style="color: gray"><em>PHP, Python:</em></span> makes the period . match newline characters.</td>
</tr>
<tr class="odd">
<td>x, re.X</td>
<td><span style="color: gray"><em>all:</em></span> ignores whitespace (outside of [] character classes) and #-style comments in the regex.</td>
</tr>
</tbody>
</table>

**python:**

Python modifiers are bit flags. To use more than one flag at the same
time, join them with bit or: |

There are alternative identifiers for the modifiers:

|      |               |
| ---- | ------------- |
| re.A | re.ASCII      |
| re.I | re.IGNORECASE |
| re.M | re.MULTILINE  |
| re.S | re.DOTALL     |
| re.X | re.VERBOSE    |

<span id="subst-note"></span>

## <span>[substitution](#subst)</span>

How to replace all occurrences of a matching pattern in a string with
the provided substitution string.

**php:**

The number of occurrences replaced can be controlled with a 4th argument
to `preg_replace`:

<div class="code">

    $s = "foo bar bar";
    preg_replace('/bar/', "baz", $s, 1);

</div>

If no 4th argument is provided, all occurrences are replaced.

**python:**

The 3rd argument to `sub` controls the number of occurrences which are
replaced.

<div class="code">

    s = 'foo bar bar'
    re.compile('bar').sub('baz', s, 1)

</div>

If there is no 3rd argument, all occurrences are replaced.

**ruby:**

The *gsub* operator returns a copy of the string with the substitution
made, if any. The *gsub\!* performs the substitution on the original
string and returns the modified string.

The *sub* and *sub\!* operators only replace the first occurrence of the
match pattern.

<span id="match-prematch-postmatch-note"></span>

## <span>[match, prematch, postmatch](#match-prematch-postmatch)</span>

How to get the substring that matched the regular expression, as well as
the part of the string before and after the matching substring.

**ruby:**

The special variables `$&`, `` $` ``, and `$'` also contain the match,
prematch, and postmatch.

<span id="group-capture-note"></span>

## <span>[group capture](#group-capture)</span>

How to get the substrings which matched the parenthesized parts of a
regular expression.

**ruby:**

Ruby has syntax for extracting a group from a match in a single
expression. The following evaluates to "1999":

<div class="code">

    "1999-07-08"[/(\d{4})-(\d{2})-(\d{2})/, 1]

</div>

<span id="named-group-capture-note"></span>

## <span>[named group capture](#named-group-capture)</span>

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

<span id="scan-note"></span>

## <span>[scan](#scan)</span>

How to return all non-overlapping substrings which match a regular
expression as an
array.

<span id="backreference-note"></span>

## <span>[backreference in match and substitution](#backreference)</span>

How to use backreferences in a regex; how to use backreferences in the
replacement string of substitution.

<span id="recursive-regex-note"></span>

## <span>[recursive regex](#recursive-regex)</span>

An examples of a recursive regex.

The example matches substrings containing balanced parens.

<span id="dates-time-note"></span>

# <span>[Date and Time](#dates-time)</span>

In ISO 8601 terminology, a *date* specifies a day in the Gregorian
calendar and a *time* does not contain date information; it merely
specifies a time of day. A data type which combines both date and time
information is convenient, but ISO 8601 doesn't provide a name for such
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

<div class="code">

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

</div>

The Linux man pages call the `tm` struct a "broken-down" date and time,
whereas the BSD man pages call it a "broken-out" date and time.

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
day to a value expressed in terms of radiation produced by
<sup>133</sup>Cs. Because the length of a solar day is irregular, leap
seconds are occasionally used to keep things in sync. This is
accomplished by occasionally adding a leap second to the end of June
30th or December 31st. The system also allows for removing the last
second of June 30th or December 31st, though as of 2014 this hasn't been
done.

<span id="broken-down-datetime-type-note"></span>

## <span>[broken-down datetime type](#broken-down-datetime-type)</span>

The data type used to hold a combined date and time.

**python:**

Python uses and exposes the `tm` struct of the C standard library.
Python has a module called `time` which is a thin wrapper to the
standard library functions which operate on this struct. Here is how get
a `tm` struct in Python:

<div class="code">

    import time
    
    utc = time.gmtime(time.time())
    t = time.localtime(time.time())

</div>

<span id="current-datetime-note"></span>

## <span>[current datetime](#current-datetime)</span>

How to get the combined date and time for the present moment in both
local time and UTC.

<span id="current-unix-epoch-note"></span>

## <span>[current unix epoch](#current-unix-epoch)</span>

How to get the current time as a Unix epoch
timestamp.

<span id="broken-down-datetime-to-unix-epoch-note"></span>

## <span>[broken-down datetime to unix epoch](#broken-down-datetime-to-unix-epoch)</span>

How to convert a datetime type to the Unix epoch which is the number of
seconds since the start of January 1, 1970 UTC.

**python:**

The Python datetime object created by `now()` and `utcnow()` has no
timezone information associated with it. The `strftime()` method assumes
a receiver with no time zone information represents a local time. Thus
it is an error to call `strftime()` on the return value of `utcnow()`.

Here are two different ways to get the current Unix epoch. The second
way is faster:

<div class="code">

    import calendar
    import datetime
    
    int(datetime.datetime.now().strftime('%s'))
    calendar.timegm(datetime.datetime.utcnow().utctimetuple())

</div>

Replacing `now()` with `utcnow()` in the first way, or `utcnow()` with
`now()` in the second way produces an incorrect
value.

<span id="unix-epoch-to-broken-down-datetime-note"></span>

## <span>[unix epoch to broken-down datetime](#unix-epoch-to-broken-down-datetime)</span>

How to convert the Unix epoch to a broken-down datetime.

<span id="fmt-datetime-note"></span>

## <span>[format datetime](#fmt-datetime)</span>

How to format a datetime as a string using using a string of format
specifiers.

The format specifiers used by the `strftime` function from the standard
C library and the Unix `date` command:

<table>
<thead>
<tr class="header">
<th></th>
<th>numeric</th>
<th>alphanumeric</th>
<th>notes</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><strong>year</strong></td>
<td>%Y %C%y</td>
<td></td>
<td>%C and %y are the first two and last two digits of a 4 digit year</td>
</tr>
<tr class="even">
<td><strong>month</strong></td>
<td>%m</td>
<td>%B %b %h</td>
<td>%m is zero padded in {01, …, 12}<br />
%h is blank padded in {1, …, 12}</td>
</tr>
<tr class="odd">
<td><strong>day of month</strong></td>
<td>%d %e</td>
<td></td>
<td>%d is zero padded in {01, …, 31}<br />
%e is blank padded in {1, …, 31}</td>
</tr>
<tr class="even">
<td><strong>hour</strong></td>
<td>%H %k</td>
<td>%I%p %l%p</td>
<td>%H and %k are in zero and blank padded</td>
</tr>
<tr class="odd">
<td><strong>minute</strong></td>
<td>%M</td>
<td></td>
<td>%M is zero padded in the range {00, …, 59}</td>
</tr>
<tr class="even">
<td><strong>second</strong></td>
<td>%S</td>
<td></td>
<td>%S is zero padded, due to leap seconds it is in the range {00, …, 60}</td>
</tr>
<tr class="odd">
<td><strong>day of year</strong></td>
<td>%j</td>
<td></td>
<td>%j is zero padded in the range {000, …, 366}</td>
</tr>
<tr class="even">
<td><strong>week date year</strong></td>
<td>%G %g</td>
<td></td>
<td>the ISO 8601 week date year. Used with %V and %u.</td>
</tr>
<tr class="odd">
<td><strong>week of year</strong></td>
<td>%V %U %W</td>
<td></td>
<td>%V is the ISO 8601 week of year. In {01, 53}. Used with %G<br />
%U is the week number when Sunday starts the week. In {00, 53}. Used with %Y and %C%y.<br />
%W is the week number when Monday starts the week. In {00, 53}. Used with %Y and %C%y.</td>
</tr>
<tr class="even">
<td><strong>day of week</strong></td>
<td>%u %w</td>
<td>%A %a</td>
<td>%u is in {{1, …, 7} starting at Monday<br />
%w is in {0, …, 6} starting at Sunday</td>
</tr>
<tr class="odd">
<td><strong>unix epoch</strong></td>
<td>%s</td>
<td></td>
<td></td>
</tr>
<tr class="even">
<td><strong>date</strong></td>
<td>%D %F %x</td>
<td>%v</td>
<td>%D is %m/%d/%y<br />
%F is %Y-%m-%d<br />
%x locale dependent; same as %D in US</td>
</tr>
<tr class="odd">
<td><strong>time</strong></td>
<td>%T %R %X</td>
<td>%r</td>
<td>%T is %H:%M:%S<br />
%R is %H:%M<br />
%X is locale dependent; same as %T in US<br />
%r is %I:%M:%S %p</td>
</tr>
<tr class="even">
<td><strong>date and time</strong></td>
<td></td>
<td>%c</td>
<td>locale dependent</td>
</tr>
<tr class="odd">
<td><strong>date, time, and tmz</strong></td>
<td></td>
<td>%+</td>
<td>locale dependent</td>
</tr>
<tr class="even">
<td><strong>time zone name</strong></td>
<td></td>
<td>%Z</td>
<td>the ambiguous 3 letter abbrevation; e.g. "PST"</td>
</tr>
<tr class="odd">
<td><strong>time zone offset</strong></td>
<td>%z</td>
<td></td>
<td>"-0800" for Pacific Standard Time</td>
</tr>
<tr class="even">
<td><strong>percent sign</strong></td>
<td></td>
<td>%%</td>
<td></td>
</tr>
<tr class="odd">
<td><strong>newline</strong></td>
<td></td>
<td>%n</td>
<td></td>
</tr>
<tr class="even">
<td><strong>tab</strong></td>
<td></td>
<td>%t</td>
<td></td>
</tr>
</tbody>
</table>

**php:**

PHP supports strftime but it also has its own time formatting system
used by `date`, `DateTime::format`, and `DateTime::createFromFormat`.
The letters used in the PHP time formatting system are [described
here](http://www.php.net/manual/en/datetime.createfromformat.php).

<span id="parse-datetime-note"></span>

## <span>[parse datetime](#parse-datetime)</span>

How to parse a datetime using the format notation of the `strptime`
function from the standard C library.

<span id="parse-datetime-without-fmt-note"></span>

## <span>[parse datetime w/o format](#parse-datetime-without-fmt)</span>

How to parse a date without providing a format string.

<span id="date-parts-note"></span>

## <span>[date parts](#date-parts)</span>

How to get the year, month, and day of month from a datetime.

<span id="time-parts-note"></span>

## <span>[time parts](#time-parts)</span>

How to the hour, minute, and second from a datetime.

<span id="build-datetime-note"></span>

## <span>[build broken-down datetime](#build-datetime)</span>

How to build a broken-down datetime from the date parts and the time
parts.

<span id="datetime-subtraction-note"></span>

## <span>[datetime subtraction](#datetime-subtraction)</span>

The data type that results when subtraction is performed on two combined
date and time values.

<span id="add-duration-note"></span>

## <span>[add duration](#add-duration)</span>

How to add a duration to a datetime.

A duration can easily be added to a datetime value when the value is a
Unix epoch value.

ISO 8601 distinguishes between a time interval, which is defined by two
datetime endpoints, and a duration, which is the length of a time
interval and can be defined by a unit of time such as '10 minutes'. A
time interval can also be defined by date and time representing the
start of the interval and a duration.

ISO 8601 defines [notation for
durations](http://en.wikipedia.org/wiki/ISO_8601#Durations). This
notation starts with a 'P' and uses a 'T' to separate the day and larger
units from the hour and smaller units. Observing the location relative
to the 'T' is important for interpreting the letter 'M', which is used
for both months and
minutes.

<span id="local-tmz-determination-note"></span>

## <span>[local time zone determination](#local-tmz-determination)</span>

Do datetime values include time zone information. When a datetime value
for the local time is created, how the local time zone is determined.

On Unix systems processes determine the local time zone by inspecting
the binary file `/etc/localtime`. To examine it from the command line
use `zdump`:

<div class="code">

    $ zdump /etc/localtime
    /etc/localtime  Tue Dec 30 10:03:27 2014 PST

</div>

On Windows the time zone name is stored in the registry at
`HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation\TimeZoneKeyName`.

**php:**

The default time zone can also be set in the `php.ini` file.

<div class="code">

    date.timezone = "America/Los_Angeles"

</div>

Here is the list of [timezones supported by
PHP](http://php.net/timezones).

<span id="nonlocal-tmz-note"></span>

## <span>[nonlocal time zone](#nonlocal-tmz)</span>

How to convert a datetime to the equivalent datetime in an arbitrary
time zone.

<span id="tmz-info-note"></span>

## <span>[time zone info](#tmz-info)</span>

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

<span id="daylight-savings-test-note"></span>

## <span>[daylight savings test](#daylight-savings-test)</span>

Is a datetime in daylight savings time?

<span id="microseconds-note"></span>

## <span>[microseconds](#microseconds)</span>

How to get the microseconds component of a combined date and time value.
The SI abbreviations for milliseconds and microseconds are `ms` and
`μs`, respectively. The C standard library uses the letter `u` as an
abbreviation for `micro`. Here is a struct defined in
`/usr/include/sys/time.h`:

<div class="code">

    struct timeval {
      time_t       tv_sec;   /* seconds since Jan. 1, 1970 */
      suseconds_t  tv_usec;  /* and microseconds */
    };

</div>

<span id="sleep-note"></span>

## <span>[sleep](#sleep)</span>

How to put the process to sleep for a specified number of seconds. In
Python and Ruby the default version of `sleep` supports a fractional
number of seconds.

**php:**

PHP provides `usleep` which takes an argument in microseconds:

<div class="code">

    usleep(500000);

</div>

<span id="timeout-note"></span>

## <span>[timeout](#timeout)</span>

How to cause a process to timeout if it takes too long.

Techniques relying on SIGALRM only work on Unix systems.

<span id="arrays-note"></span>

# <span>[Arrays](#arrays)</span>

What the languages call their basic container
types:

|                             | javascript | php   | python                | ruby              |
| --------------------------- | ---------- | ----- | --------------------- | ----------------- |
| [array](#array-literal)     |            | array | list, tuple, sequence | Array, Enumerable |
| [dictionary](#dict-literal) |            | array | dict, mapping         | Hash              |

**javascript:**

**php:**

PHP uses the same data structure for arrays and dictionaries.

**python:**

Python has the mutable *list* and the immutable *tuple*. Both are
*sequences*. To be a *sequence*, a class must implement
<span style="white-space: pre-wrap;">\_\_getitem\_\_</span>,
<span style="white-space: pre-wrap;">\_\_setitem\_\_</span>,
<span style="white-space: pre-wrap;">\_\_delitem\_\_</span>,
<span style="white-space: pre-wrap;">\_\_len\_\_</span>,
<span style="white-space: pre-wrap;">\_\_contains\_\_</span>,
<span style="white-space: pre-wrap;">\_\_iter\_\_</span>,
<span style="white-space: pre-wrap;">\_\_add\_\_</span>,
<span style="white-space: pre-wrap;">\_\_mul\_\_</span>,
<span style="white-space: pre-wrap;">\_\_radd\_\_</span>, and
<span style="white-space: pre-wrap;">\_\_rmul\_\_</span>.

**ruby:**

Ruby provides an *Array* datatype. If a class defines an *each* iterator
and a comparison operator \<=\>, then it can mix in the *Enumerable*
module.

<span id="array-literal-note"></span>

## <span>[literal](#array-literal)</span>

Array literal syntax.

**ruby:**

The `%w` operator splits the following string on whitespace and creates
an array of strings from the words. The character following the `%w` is
the string delimiter. If the following character is (, \[, or {, then
the character which terminates the string must be ), \], or }.

The `%W` operator is like the `%w` operator, except that double-quote
style `#{ }` expressions will be interpolated.

<span id="quote-words-note"></span>

## <span>[quote words](#quote-words)</span>

The quote words operator, which is a literal for arrays of strings where
each string contains a single word.

<span id="array-size-note"></span>

## <span>[size](#array-size)</span>

How to get the number of elements in an array.

<span id="array-empty-note"></span>

## <span>[empty test](#array-empty)</span>

How to test whether an array is empty.

<span id="array-lookup-note"></span>

## <span>[lookup](#array-lookup)</span>

How to access a value in an array by index.

**python:**

A negative index refers to the *length - index* element.

<div class="code">

    >>> a = [1, 2, 3]
    >>> a[-1]
    3

</div>

**ruby:**

A negative index refers to to the *length - index* element.

<span id="array-update-note"></span>

## <span>[update](#array-update)</span>

How to update the value at an index.

<span id="array-out-of-bounds-note"></span>

## <span>[out-of-bounds behavior](#array-out-of-bounds)</span>

What happens when the value at an out-of-bounds index is referenced.

<span id="array-element-index-note"></span>

## <span>[element index](#array-element-index)</span>

How to get the index of an element in an array.

**php:**

Setting the 3rd argument of `array_search` to true makes the search use
`===` for an equality test. Otherwise the `==` test is performed, which
makes use of implicit type conversions.

<span id="array-slice-note"></span>

## <span>[slice](#array-slice)</span>

How to slice a subarray from an array by specifying a start index and an
end index; how to slice a subarray from an array by specifying an offset
index and a length index.

**python:**

Slices can leave the first or last index unspecified, in which case the
first or last index of the sequence is used:

<div class="code">

    >>> a=[1, 2, 3, 4, 5]
    >>> a[:3]
    [1, 2, 3]

</div>

Python has notation for taking every nth element:

<div class="code">

    >>> a=[1, 2, 3, 4, 5]
    >>> a[::2] 
    [1, 3, 5]

</div>

The third argument in the colon-delimited slice argument can be
negative, which reverses the order of the result:

<div class="code">

    >>> a = [1, 2, 3, 4]
    >>> a[::-1]
    [4, 3, 2, 1]

</div>

<span id="array-slice-to-end-note"></span>

## <span>[slice to end](#array-slice-to-end)</span>

How to slice to the end of an array.

The examples take all but the first element of the array.

<span id="array-back-note"></span>

## <span>[manipulate back](#array-back)</span>

How to add and remove elements from the back or high index end of an
array.

These operations can be used to use the array as a stack.

<span id="array-front-note"></span>

## <span>[manipulate front](#array-front)</span>

How to add and remove elements from the front or low index end of an
array.

These operations can be used to use the array as a stack. They can be
used with the operations that manipulate the back of the array to use
the array as a queue.

<span id="array-concatenation-note"></span>

## <span>[concatenate](#array-concatenation)</span>

How to create an array by concatenating two arrays; how to modify an
array by concatenating another array to the end of it.

<span id="replicate-array-note"></span>

## <span>[replicate](#replicate-array)</span>

How to create an array containing the same value replicated *n* times.

<span id="array-copy-note"></span>

## <span>[copy](#array-copy)</span>

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

<div class="code">

    a2 = a[:]

</div>

`list(v)` always returns a list, but `v[:]` returns a value of the same
as `v`. The slice operator can be used in this manner on strings and
tuples but there is little incentive to do so since both are immutable.

`copy.copy` can be used to make a shallow copy on types that don't
support the slice operator such as a dictionary. Like the slice operator
`copy.copy` returns a value with the same type as the argument.

<span id="array-as-func-arg-note"></span>

## <span>[array as function argument](#array-as-func-arg)</span>

How an array is passed to a function when provided as an argument.

<span id="iterate-over-array-note"></span>

## <span>[iterate over elements](#iterate-over-array)</span>

How to iterate over the elements of an
array.

<span id="indexed-array-iteration-note"></span>

## <span>[iterate over indices and elements](#indexed-array-iteration)</span>

How to iterate over the element-index pairs.

<span id="range-iteration-note"></span>

## <span>[iterate over range](#range-iteration)</span>

Iterate over a range without instantiating it as a list.

<span id="range-array-note"></span>

## <span>[instantiate range as array](#range-array)</span>

How to convert a range to an array.

Python 3 ranges and Ruby ranges implement some of the functionality of
arrays without allocating space to hold all the elements.

**python:**

In Python 2 `range()` returns a list.

In Python 3 `range()` returns an object which implements the immutable
sequence API.

**ruby:**

The Range class includes the Enumerable module.

<span id="array-reverse-note"></span>

## <span>[reverse](#array-reverse)</span>

How to create a reversed copy of an array, and how to reverse an array
in place.

**python:**

`reversed` returns an iterator which can be used in a `for/in`
construct:

<div class="code">

    print("counting down:")
    for i in reversed([1, 2, 3]):
      print(i)

</div>

`reversed` can be used to create a reversed list:

<div class="code">

    a = list(reversed([1, 2, 3]))

</div>

<span id="array-sort-note"></span>

## <span>[sort](#array-sort)</span>

How to create a sorted copy of an array, and how to sort an array in
place. Also, how to set the comparison function when sorting.

**php:**

`usort` sorts an array in place and accepts a comparison function as a
2nd argument:

<div class="code">

    function cmp($x, $y) {
      $lx = strtolower($x);
      $ly = strtolower($y);
      if ( $lx < $ly ) { return -1; }
      if ( $lx == $ly ) { return 0; }
      return 1;
    }
    
    $a = ["b", "A", "a", "B"];
    
    usort($a, "cmp");

</div>

**python:**

In Python 2 it is possible to specify a binary comparision function when
calling `sort`:

<div class="code">

    a = [(1, 3), (2, 2), (3, 1)]
    
    a.sort(cmp=lambda a, b: -1 if a[1] < b[1] else 1)
    
    # a now contains:
    [(3, 1), (2, 2), (1, 3)]

</div>

In Python 3 the `cmp` parameter was removed. One can achieve the same
effect by defining `cmp` method on the class of the list element.

<span id="array-dedupe-note"></span>

## <span>[dedupe](#array-dedupe)</span>

How to remove extra occurrences of elements from an array.

**python:**

Python sets support the `len`, `in`, and `for` operators. It may be more
efficient to work with the result of the set constructor directly rather
than convert it back to a list.

<span id="membership-note"></span>

## <span>[membership](#membership)</span>

How to test for membership in an array.

<span id="intersection-note"></span>

## <span>[intersection](#intersection)</span>

How to compute an intersection.

**python:**

Python has literal notation for sets:

<div class="code">

    {1, 2, 3}

</div>

Use `set` and `list` to convert lists to sets and vice versa:

<div class="code">

    a = list({1, 2, 3})
    ensemble = set([1, 2, 3])

</div>

**ruby:**

The intersect operator `&` always produces an array with no duplicates.

<span id="union-note"></span>

## <span>[union](#union)</span>

**ruby:**

The union operator `|` always produces an array with no duplicates.

<span id="set-diff-note"></span>

## <span>[relative complement, symmetric difference](#set-diff)</span>

How to compute the relative complement of two arrays or sets; how to
compute the symmetric difference.

**ruby:**

If an element is in the right argument, then it will not be in the
return value even if it is contained in the left argument multiple
times.

<span id="map-note"></span>

## <span>[map](#map)</span>

Create an array by applying a function to each element of a source
array.

**ruby:**

The `map!` method applies the function to the elements of the array in
place.

`collect` and `collect!` are synonyms for `map` and `map!`.

<span id="filter-note"></span>

## <span>[filter](#filter)</span>

Create an array containing the elements of a source array which match a
predicate.

**ruby:**

The in place version is `select!`.

`reject` returns the complement of `select`. `reject!` is the in place
version.

The `partition` method returns two arrays:

<div class="code">

    a = [1, 2, 3]
    lt2, ge2 = a.partition { |n| n < 2 }

</div>

<span id="reduce-note"></span>

## <span>[reduce](#reduce)</span>

Return the result of applying a binary operator to all the elements of
the array.

**python:**

`reduce` is not needed to sum a list of numbers:

<div class="code">

    sum([1, 2, 3])

</div>

**ruby:**

The code for the reduction step can be provided by name. The name can be
a symbol or a string:

<div class="code">

    [1, 2, 3].inject(:+)
    
    [1, 2, 3].inject("+")
    
    [1, 2, 3].inject(0, :+)
    
    [1, 2, 3].inject(0, "+")

</div>

<span id="universal-existential-test-note"></span>

## <span>[universal and existential tests](#universal-existential-test)</span>

How to test whether a condition holds for all members of an array; how
to test whether a condition holds for at least one member of any array.

A universal test is always true for an empty array. An existential test
is always false for an empty array.

A existential test can readily be implemented with a filter. A universal
test can also be implemented with a filter, but it is more work: one
must set the condition of the filter to the negation of the predicate
and test whether the result is empty.

<span id="shuffle-sample-note"></span>

## <span>[shuffle and sample](#shuffle-sample)</span>

How to shuffle an array. How to extract a random sample from an array.

**php:**

The `array_rand` function returns a random sample of the indices of an
array. The result can easily be converted to a random sample of array
values:

<div class="code">

    $a = [1, 2, 3, 4];
    $sample = [];
    foreach (array_rand($a, 2) as $i) { array_push($sample, $a[$i]); }

</div>

<span id="flatten-note"></span>

## <span>[flatten](#flatten)</span>

How to flatten nested arrays by one level or completely.

When nested arrays are flattened by one level, the depth of each element
which is not in the top level array is reduced by one.

Flattening nested arrays completely leaves no nested arrays. This is
equivalent to extracting the leaf nodes of a tree.

**php, python:**

To flatten by one level use reduce. Remember to handle the case where an
element is not array.

To flatten completely write a recursive function.

<span id="zip-note"></span>

## <span>[zip](#zip)</span>

How to interleave arrays. In the case of two arrays the result is an
array of pairs or an associative list.

<span id="dictionaries-note"></span>

# <span>[Dictionaries](#dictionaries)</span>

<span id="dict-literal-note"></span>

## <span>[literal](#dict-literal)</span>

The syntax for a dictionary literal.

<span id="dict-size-note"></span>

## <span>[size](#dict-size)</span>

How to get the number of dictionary keys in a dictionary.

<span id="dict-lookup-note"></span>

## <span>[lookup](#dict-lookup)</span>

How to lookup a dictionary value using a dictionary key.

<span id="dict-missing-key-note"></span>

## <span>[missing key behavior](#dict-missing-key)</span>

What happens when a lookup is performed on a key that is not in a
dictionary.

**python:**

Use `dict.get()` to avoid handling `KeyError` exceptions:

<div class="code">

    d = {}
    d.get('lorem')      # returns None
    d.get('lorem', '')  # returns ''

</div>

<span id="dict-key-check-note"></span>

## <span>[is key present](#dict-key-check)</span>

How to check for the presence of a key in a dictionary without raising
an exception. Distinguishes from the case where the key is present but
mapped to null or a value which evaluates to false.

<span id="dict-delete-note"></span>

## <span>[delete](#dict-delete)</span>

How to remove a key/value pair from a
dictionary.

<span id="dict-assoc-array-note"></span>

## <span>[from array of pairs, from even length array](#dict-assoc-array)</span>

How to create a dictionary from an array of pairs; how to create a
dictionary from an even length array.

<span id="dict-merge-note"></span>

## <span>[merge](#dict-merge)</span>

How to merge the values of two dictionaries.

In the examples, if the dictionaries `d1` and `d2` share keys then the
values from `d2` will be used in the merged dictionary.

<span id="dict-invert-note"></span>

## <span>[invert](#dict-invert)</span>

How to turn a dictionary into its inverse. If a key 'foo' is mapped to
value 'bar' by a dictionary, then its inverse will map the key 'bar' to
the value 'foo'. However, if multiple keys are mapped to the same value
in the original dictionary, then some of the keys will be discarded in
the inverse.

<span id="dict-iter-note"></span>

## <span>[iteration](#dict-iter)</span>

How to iterate through the key/value pairs in a dictionary.

**python:**

In Python 2.7 `dict.items()` returns a list of pairs and
`dict.iteritems()` returns an iterator on the list of pairs.

In Python 3 `dict.items()` returns an iterator and `dict.iteritems()`
has been removed.

<span id="dict-key-val-note"></span>

## <span>[keys and values as arrays](#dict-key-val)</span>

How to convert the keys of a dictionary to an array; how to convert the
values of a dictionary to an array.

**python:**

In Python 3 `dict.keys()` and `dict.values()` return read-only views
into the dict. The following code illustrates the change in behavior:

<div class="code">

    d = {}
    keys = d.keys()
    d['foo'] = 'bar'
    
    if 'foo' in keys:
      print('running Python 3')
    else:
      print('running Python 2')

</div>

<span id="dict-sort-values-note"></span>

## <span>[sort by values](#dict-sort-values)</span>

How to iterate through the key-value pairs in the order of the values.

<span id="dict-default-val-note"></span>

## <span>[default value, computed value](#dict-default-val)</span>

How to create a dictionary with a default value for missing keys; how to
compute and store the value on lookup.

**php:**

Extend `ArrayObject` to compute values on lookup:

<div class="code">

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

</div>

<span id="functions-note"></span>

# <span>[Functions](#functions)</span>

Python has both functions and methods. Ruby only has methods: functions
defined at the top level are in fact methods on a special main object.
Perl subroutines can be invoked with a function syntax or a method
syntax.

<span id="def-func-note"></span>

## <span>[define](#def-func)</span>

How to define a function.

<span id="invoke-func-note"></span>

## <span>[invoke](#invoke-func)</span>

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

<span id="apply-func-note"></span>

## <span>[apply function to array](#apply-func)</span>

How to apply a function to an array.

**perl:**

Perl passes the elements of arrays as individual arguments. In the
following invocation, the function `foo()` does not know which arguments
came from which array. For that matter it does not know how many arrays
were used in the invocation:

<div class="code">

    foo(@a, @b);

</div>

If the elements must be kept in their respective arrays the arrays must
be passed by reference:

<div class="code">

    sub foo {
      my @a = @{$_[0]};
      my @b = @{$_[1]};
    }
    
    foo(\@a, \@b);

</div>

When hashes are used as arguments, each key and value becomes its own
argument.

<span id="missing-arg-note"></span>

## <span>[missing argument behavior](#missing-arg)</span>

What happens when a function is invoked with too few arguments.

<span id="extra-arg-note"></span>

## <span>[extra argument behavior](#extra-arg)</span>

What happens when a function is invoked with too many arguments.

<span id="default-arg-note"></span>

## <span>[default argument](#default-arg)</span>

How to declare a default value for an argument.

<span id="variadic-func-note"></span>

## <span>[variadic function](#variadic-func)</span>

How to write a function which accepts a variable number of argument.

**python:**

This function accepts one or more arguments. Invoking it without any
arguments raises a `TypeError`:

<div class="code">

    def poker(dealer, *players):
      ...

</div>

**ruby:**

This function accepts one or more arguments. Invoking it without any
arguments raises an `ArgumentError`:

<div class="code">

    def poker(dealer, *players)
      ...
    end

</div>

<span id="param-alias-note"></span>

## <span>[parameter alias](#param-alias)</span>

How to make a parameter an alias of a variable in the caller.

<span id="named-param-note"></span>

## <span>[named parameters](#named-param)</span>

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

<div class="code">

    def fequal(x, y, **kwargs):
      eps = opts.get('eps') or 0.01
      return abs(x - y) < eps

</div>

In Python 3 named parameters can be made mandatory:

<div class="code">

    def fequal(x, y, *, eps):
      return abs(x-y) < eps
    
    fequal(1.0, 1.001, eps=0.01)  # True
    
    fequal(1.0, 1.001)                 # raises TypeError

</div>

**ruby:**

In Ruby 2.1 named parameters can be made mandatory:

<div class="code">

    def fequals(x, y, eps:)
      (x - y).abs < eps
    end
    
    # false:
    fequals(1.0, 1.001, eps: 0.1**10)
    # ArgumentError:
    fequals(1.0, 1.001)

</div>

<span id="retval-note"></span>

## <span>[return value](#retval)</span>

How the return value of a function is determined.

<span id="multiple-retval-note"></span>

## <span>[multiple return values](#multiple-retval)</span>

How to return multiple values from a function.

<span id="anonymous-func-literal-note"></span>

## <span>[anonymous function literal](#anonymous-func-literal)</span>

The syntax for an anonymous function literal; i.e. a lambda function.

**python:**

Python lambdas cannot contain newlines or semicolons, and thus are
limited to a single statement or expression. Unlike named functions, the
value of the last statement or expression is returned, and a *return* is
not necessary or permitted. Lambdas are closures and can refer to local
variables in scope, even if they are returned from that scope.

If a closure function is needed that contains more than one statement,
use a nested function:

<div class="code">

    def make_nest(x):
        b = 37
        def nest(y):
            c = x*y
            c *= b
            return c
        return nest
    
    n = make_nest(12*2)
    print(n(23))

</div>

Python closures are read only.

A nested function can be returned and hence be invoked outside of its
containing function, but it is not visible by its name outside of its
containing function.

**ruby:**

The following lambda and Proc object behave identically:

<div class="code">

    sqr = lambda { |x| x * x }
    
    sqr = Proc.new {|x| x * x }

</div>

With respect to control words, Proc objects behave like blocks and
lambdas like functions. In particular, when the body of a Proc object
contains a `return` or `break` statement, it acts like a `return` or
`break` in the code which invoked the Proc object. A `return` in a
lambda merely causes the lambda to exit, and a `break` inside a lambda
must be inside an appropriate control structure contained with the
lambda body.

Ruby are alternate syntax for defining lambdas and invoking them:

<div class="code">

    sqr = ->(x) {x*x}
    
    sqr.(2)

</div>

<span id="invoke-anonymous-func-note"></span>

## <span>[invoke anonymous function](#invoke-anonymous-func)</span>

The syntax for invoking an anonymous function.

<span id="func-as-val-note"></span>

## <span>[function as value](#func-as-val)</span>

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

<span id="private-state-func-note"></span>

## <span>[function with private state](#private-state-func)</span>

How to create a function with private state which persists between
function invocations.

**python:**

Here is a technique for creating private state which exploits the fact
that the expression for a default value is evaluated only once:

<div class="code">

    def counter(_state=[0]):
      _state[0] += 1
      return _state[0]
    
    print(counter())

</div>

<span id="closure-note"></span>

## <span>[closure](#closure)</span>

How to create a first class function with access to the local variables
of the local scope in which it was created.

**python:**

Python 2 has limited closures: access to local variables in the
containing scope is read only and the bodies of anonymous functions must
consist of a single expression.

Python 3 permits write access to local variables outside the immediate
scope when declared with `nonlocal`.

<span id="generator-note"></span>

## <span>[generator](#generator)</span>

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

<span id="decorator-note"></span>

## <span>[decorator](#decorator)</span>

A decorator replaces an invocation of one function with another in a way
that that is imperceptible to the client.

Normally a decorator will add a small amount of functionality to the
original function which it invokes. A decorator can modify the arguments
before passing them to the original function or modify the return value
before returning it to the client. Or it can leave the arguments and
return value unmodified but perform a side effect such as logging the
call.

<span id="invoke-op-like-func-note"></span>

## <span>[invoke operator like function](#invoke-op-like-func)</span>

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

<span id="execution-control-note"></span>

# <span>[Execution Control](#execution-control)</span>

<span id="if-note"></span>

## <span>[if](#if)</span>

The conditional branch statement.

**php:**

PHP has the following alternate syntax for `if` statements:

<div class="code">

    if ($n == 0): 
      echo "no hits\n";
    elseif ($n == 1):
      echo "one hit\n";
    else:
      echo "$n hits\n";
    endif;

</div>

**ruby:**

If an `if` statement is the last statement executed in a function, the
return value is the value of the branch that executed.

Ruby `if` statements are expressions. They can be used on the right hand
side of assignments:

<div class="code">

    m = if n
      1
    else
      0
    end

</div>

<span id="switch-note"></span>

## <span>[switch](#switch)</span>

A statement which branches based on the value of an expression.

<span id="while-note"></span>

## <span>[while](#while)</span>

How to loop over a block while a condition is true.

**php:**

PHP provides a `do-while` loop. The body of such a loop is guaranteed to
execute at least once.

<div class="code">

    $i = 0;
    do {
        echo $i;
    } while ($i > 0);

</div>

**ruby:**

Ruby provides a loop with no exit condition:

<div class="code">

    def yes(expletive="y")
      loop do
       puts expletive
      end
    end

</div>

Ruby also provides the `until` loop.

Ruby loops can be used in expression contexts but they always evaluate
to `nil`.

<span id="for-note"></span>

## <span>[for](#for)</span>

How to write a C-style for loop.

<span id="break-note"></span>

## <span>[break](#break)</span>

A `break` statement exits a `while` or `for` loop immediately.

<span id="continue-note"></span>

## <span>[continue](#continue)</span>

A `continue` statement skips ahead to the next iteration of a `while` or
`for` loop.

**ruby:**

There is also a `redo` statement, which restarts the current iteration
of a loop.

<span id="statement-modifiers-note"></span>

## <span>[statement modifiers](#statement-modifiers)</span>

Clauses added to the end of a statement to control execution.

Ruby has conditional statement modifiers. Ruby also has looping
statement modifiers.

**ruby:**

Ruby has the looping statement modifiers `while` and `until`:

<div class="code">

    i = 0
    i += 1 while i < 10
    
    j = 10
    j -= 1 until j < 0

</div>

<span id="exceptions-note"></span>

# <span>[Exceptions](#exceptions)</span>

<span id="base-exc-note"></span>

## <span>[base exception](#base-exc)</span>

The base exception type or class that can be used to catch all
exceptions.

<span id="predefined-exc-note"></span>

## <span>[predefined exceptions](#predefined-exc)</span>

A list of the more commonly encountered exceptions.

**python:**

Code for inspecting the descendants of a base class:

<div class="code">

    def print_class_hierarchy(cls, indent=0):
        print(' ' * indent, cls.__name__)
        for subclass in cls.__subclasses__():
            print_class_hierarchy(subclass, indent + 2)

</div>

The complete Python 3.5 exception hierarchy:

<div class="code">

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

</div>

<span id="raise-exc-note"></span>

## <span>[raise exception](#raise-exc)</span>

How to raise exceptions.

**ruby:**

Ruby has a *throw* keyword in addition to *raise*. *throw* can have a
symbol as an argument, and will not convert a string to a RuntimeError
exception.

<span id="catch-all-handler-note"></span>

## <span>[catch-all handler](#catch-all-handler)</span>

How to catch exceptions.

**php:**

PHP code must specify a variable name for the caught exception.
*Exception* is the top of the exception hierarchy and will catch all
exceptions.

Internal PHP functions usually do not throw exceptions. They can be
converted to exceptions with this signal
    handler:

<div class="code">

    function exception_error_handler($errno, $errstr, $errfile, $errline ) {
        throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
    }
    set_error_handler("exception_error_handler");

</div>

**ruby:**

A *rescue Exception* clause will catch any exception. A *rescue* clause
with no exception type specified will catch exceptions that are
subclasses of *StandardError*. Exceptions outside *StandardError* are
usually unrecoverable and hence not handled in code.

In a *rescue* clause, the *retry* keyword will cause the *begin* clause
to be re-executed.

In addition to *begin* and *rescue*, ruby has *catch*:

<div class="code">

    catch (:done) do
      loop do
        retval = work
        throw :done if retval < 10
      end
    end

</div>

<span id="re-raise-exc-note"></span>

## <span>[re-raise exception](#re-raise-exc)</span>

How to re-raise an exception preserving the original stack trace.

**python:**

If the exception is assigned to a variable in the `except` clause and
the variable is used as the argument to `raise`, then a new stack trace
is created.

**ruby:**

If the exception is assigned to a variable in the `rescue` clause and
the variable is used as the argument to `raise`, then the original stack
trace is preserved.

<span id="last-exc-global-note"></span>

## <span>[global variable for last exception](#last-exc-global)</span>

The global variable name for the last exception raised.

<span id="def-exc-note"></span>

## <span>[define exception](#def-exc)</span>

How to define a new variable class.

<span id="handle-exc-note"></span>

## <span>[handle exception](#handle-exc)</span>

How to catch exceptions of a specific type and assign the exception a
name.

**php:**

PHP exceptions when caught must always be assigned a variable name.

<span id="finally-block-note"></span>

## <span>[finally block](#finally-block)</span>

A block of statements that is guaranteed to be executed even if an
exception is thrown or caught.

<span id="threads-note"></span>

# <span>[Threads](#threads)</span>

<span id="start-thread-note"></span>

## <span>[start thread](#start-thread)</span>

**ruby:**

Ruby MRI threads are operating system threads, but a global interpreter
lock prevents more than one thread from executing Ruby code at a time.

<span id="wait-on-thread-note"></span>

## <span>[wait on thread](#wait-on-thread)</span>

How to make a thread wait for another thread to finish.

<div id="license-area" class="license-area">

[issue tracker](https://github.com/clarkgrubb/hyperpolyglot/issues) |
content of this page licensed under [creative commons
attribution-sharealike 3.0](http://creativecommons.org/licenses/by-sa/3.0/)  

</div>

burp-extension
==============

This is an extension for the web application security testing platform [Burp](https://portswigger.net/burp/) that allows reports to be uploaded directly to Code Dx.

Building
--------

This project is built with [sbt](http://www.scala-sbt.org/) and is packaged with the sbt-assembly plugin.

To build, run `sbt compile assembly` from the project directory. The compiled jar will be in the target directory.

To generate the project files for use with eclipse, run `sbt eclipse` from the project directory.

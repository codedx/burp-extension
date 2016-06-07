name := "burp-extension"
organization := "com.secdec.codedx"
version := "1.0-SNAPSHOT"
description := "Code Dx Burp Extension"

publishMavenStyle := true
crossPaths := false
autoScalaLibrary := false

libraryDependencies ++= Seq(
  "org.apache.httpcomponents" % "httpclient" % "4.5.2",
  "org.apache.httpcomponents" % "httpcore" % "4.4.4",
  "org.apache.httpcomponents" % "httpmime" % "4.5.2",
  "commons-logging" % "commons-logging" % "1.2",
  "org.json" % "json" % "20160212"
)
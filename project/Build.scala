import sbt._
import Keys._
import complete.DefaultParsers._

object BuildDef extends Build {
	lazy val root = Project("burp-extension", file("."))
		.settings(
			name := "burp-extension",
			organization := "com.codedx",
			description := "Code Dx Burp Extension",

			// set version by editing .version file
			version <<= Def.setting { IO.read(file(".version")).trim },

			publishMavenStyle := true,
			crossPaths := false,
			autoScalaLibrary := false,

			libraryDependencies ++= Seq(
				"org.apache.httpcomponents" % "httpclient" % "4.5.2",
				"org.apache.httpcomponents" % "httpcore" % "4.4.4",
				"org.apache.httpcomponents" % "httpmime" % "4.5.2",
				"commons-logging" % "commons-logging" % "1.2",
				"org.json" % "json" % "20160212",
				"com.github.jiconfont" % "jiconfont-swing" % "1.0.0",
				"com.github.jiconfont" % "jiconfont-font_awesome" % "4.5.0.3"
			),

			(commands in Global) <++= Def.setting {
				Seq(withReleaseVersionCommand)
			}
		)

	private lazy val withReleaseVersionParser = Space ~> (token(StringBasic, "<version>") ~ token(Space ~> StringBasic, "<command>"))
	private def withReleaseVersionCommand = Command("withReleaseVersion")(_ => withReleaseVersionParser) { case (state, (buildVersion, buildCommand)) =>
		println(s"Running `$buildCommand` for release version $buildVersion...")

		val extracted = Project extract state
		val cmdState = extracted.append(Seq(version := buildVersion), state)
		Command.process(buildCommand, cmdState)
		state
	}
}
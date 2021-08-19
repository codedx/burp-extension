// param for RELEASE_VERSION - if empty, generate snapshot build, otherwise, release build
// this pipeline doesn't do release management (yet), so test->release is still a manual process

pipeline {
	parameters {
		string name: 'RELEASE_VERSION', defaultValue: '', description: '(e.g., 1.0.0, leave blank for current snapshot)', trim: true
	}

	agent {
		// Code Dx build environment already has SBT and company
		label 'codedx-build-small'
	}

	stages {
		stage('Build extension') {
			steps {
				script {
					if (!params.RELEASE_VERSION.isEmpty()) {
						writeFile file: '.version', text: params.RELEASE_VERSION
					}
				}

				withCache(name: 'codedx-burp-cache', baseFolder: env.HOME, contents: '.sbt .ivy2') {
					sbt tasks: 'compile assembly'
				}
			}

			post {
				success {
					archiveArtifacts artifacts: 'target/burp-extension-assembly-*.jar', fingerprint: true, onlyIfSuccessful: true

					//TODO: analyze with Code Dx

					script {
						if (!params.RELEASE_VERSION.isEmpty()) {
							currentBuild.displayName = "Release ${params.RELEASE_VERSION}"
							slack.info "Burp Extension release build ${params.RELEASE_VERSION} complete"
						}
					}
				}
			}
		}
	}

	post {
		failure {
			script {
				slack.error 'Burp Extension build FAILED'
			}
		}
	}
}

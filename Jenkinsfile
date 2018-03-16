#!groovy
pipeline {
  agent any

  options {
      buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '5'))
    }

  stages {
    // Clean the workspace
    stage('Clean the workspace') {
      steps {
          step([$class: 'WsCleanup'])
      }
    }

    // Checkout the repository
    stage('Checkout from GitHub') {
        steps {
            checkout scm
        }
    }

    stage('Build') {
        steps {
            sh "mvn clean package"
        }
    }

    stage('Deploy') {
        steps {
            sh "mvn deploy"
        }
  }
}
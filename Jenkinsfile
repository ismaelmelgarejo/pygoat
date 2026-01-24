pipeline {
  agent any
  options { timestamps() }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Smoke') {
      steps {
        sh 'echo "Repo listo:"'
        sh 'ls -la'
      }
    }

    stage('Python deps + tests (opcional)') {
      agent {
        docker {
          image 'python:3.11-slim'
        }
      }
      steps {
        sh 'python --version'
        sh 'pip install -U pip'
        // Si existe requirements.txt lo instala; si no, no rompe el build
        sh 'test -f requirements.txt && pip install -r requirements.txt || true'
        // Si existe pytest, lo corre; si no, no rompe el build
        sh 'pytest -q || true'
      }
    }
  }
}

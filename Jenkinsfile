pipeline {
  agent any
  options { timestamps() }

  environment {
    // URLs desde Jenkins (contenedor) hacia tu host:
    // - Docker Desktop (Win/Mac): host.docker.internal funciona.
    // - Linux: si no funciona, usa http://172.17.0.1:<puerto>
    DOJO_URL           = "http://host.docker.internal:8080"
    DTRACK_BACKEND_URL = "http://host.docker.internal:8084"

    PRODUCT_TYPE_NAME  = "Training"
    PRODUCT_NAME       = "PyGoat"
    ENGAGEMENT_NAME    = "Jenkins CI"

    REPORTS_DIR        = "reports"

    GITLEAKS_IMAGE     = "zricethezav/gitleaks:v8.30.0"
    SYFT_IMAGE         = "anchore/syft:latest"
  }

  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Prep') {
      steps {
        sh '''
          set -e
          mkdir -p "$REPORTS_DIR"
        '''
      }
    }

    stage('Secrets Scan - gitleaks') {
      steps {
        sh '''
          set -euo pipefail

          docker run --rm \
            -v "$WORKSPACE:/repo" -w /repo \
            "$GITLEAKS_IMAGE" detect \
              --source . \
              --report-format json \
              --report-path "$REPORTS_DIR/gitleaks.json" \
              --exit-code 0

          LEAKS="$(jq 'length' "$REPORTS_DIR/gitleaks.json")"
          echo "Gitleaks findings: $LEAKS"
          echo "{ \"gitleaks\": { \"findings\": $LEAKS } }" > "$REPORTS_DIR/summary.json"

          # Opcional: decide si quieres fallar por secretos:
          if [ "$LEAKS" -gt 0 ]; then
            echo "WARNING: Hay secretos detectados (puedes decidir fallar aquí si tu ejercicio lo pide)."
          fi
        '''
      }
    }

    stage('SAST - Bandit') {
      steps {
        sh '''
          set -euo pipefail

          docker run --rm \
            -v "$WORKSPACE:/src" -w /src \
            python:3.12-slim bash -lc '
              pip -q install bandit &&
              bandit -r . -f json -o "'"$REPORTS_DIR"'/bandit.json" || true
            '

          BANDIT_HIGH="$(jq '[.results[] | select(.issue_severity=="HIGH")] | length' "$REPORTS_DIR/bandit.json")"
          echo "Bandit HIGH: $BANDIT_HIGH"

          jq --argjson bh "$BANDIT_HIGH" \
            '. + {bandit:{high:$bh}}' \
            "$REPORTS_DIR/summary.json" > "$REPORTS_DIR/summary.tmp.json"
          mv "$REPORTS_DIR/summary.tmp.json" "$REPORTS_DIR/summary.json"
        '''
      }
    }

    stage('SCA - SBOM -> Dependency-Track -> FPF Export') {
      environment {
        DTRACK_API_KEY = credentials('dtrack_api_key')
      }
      steps {
        sh '''
          set -euo pipefail

          # 1) Generar SBOM CycloneDX (Syft)
          docker run --rm \
            -v "$WORKSPACE:/src" -w /src \
            "$SYFT_IMAGE" dir:. -o cyclonedx-json > "$REPORTS_DIR/sbom.cdx.json"

          # 2) Subir SBOM a Dependency-Track (/api/v1/bom)
          UPLOAD_RESP="$(curl -sS -X POST "$DTRACK_BACKEND_URL/api/v1/bom" \
            -H "X-Api-Key: $DTRACK_API_KEY" \
            -F "autoCreate=true" \
            -F "projectName=$PRODUCT_NAME" \
            -F "projectVersion=$BUILD_NUMBER" \
            -F "bom=@$REPORTS_DIR/sbom.cdx.json")"

          echo "$UPLOAD_RESP" > "$REPORTS_DIR/dtrack-upload.json"
          TOKEN="$(echo "$UPLOAD_RESP" | jq -r '.token')"
          echo "Dependency-Track upload token: $TOKEN"

          # 3) Esperar a que termine el procesamiento (/api/v1/bom/token/<token>)
          for i in $(seq 1 60); do
            PROCESSING="$(curl -sS -H "X-Api-Key: $DTRACK_API_KEY" "$DTRACK_BACKEND_URL/api/v1/bom/token/$TOKEN")"
            echo "processing=$PROCESSING (try $i/60)"
            [ "$PROCESSING" = "false" ] && break
            sleep 5
          done

          # 4) Lookup del proyecto y exportar findings FPF
          ENCODED_NAME="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$PRODUCT_NAME")"
          ENCODED_VER="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$BUILD_NUMBER")"

          PROJ="$(curl -sS -H "X-Api-Key: $DTRACK_API_KEY" \
            "$DTRACK_BACKEND_URL/api/v1/project/lookup?name=$ENCODED_NAME&version=$ENCODED_VER")"
          echo "$PROJ" > "$REPORTS_DIR/dtrack-project.json"

          UUID="$(echo "$PROJ" | jq -r '.uuid')"
          echo "Project UUID: $UUID"

          curl -sS -H "X-Api-Key: $DTRACK_API_KEY" \
            "$DTRACK_BACKEND_URL/api/v1/finding/project/$UUID/export" \
            -o "$REPORTS_DIR/dtrack-fpf.json"

          # 5) Security gate (CRITICAL/HIGH) desde FPF (vulnerability.severity)
          DT_CRIT="$(jq '[.findings[] | select(.vulnerability.severity=="CRITICAL")] | length' "$REPORTS_DIR/dtrack-fpf.json")"
          DT_HIGH="$(jq '[.findings[] | select(.vulnerability.severity=="HIGH")] | length' "$REPORTS_DIR/dtrack-fpf.json")"

          echo "Dependency-Track CRITICAL: $DT_CRIT"
          echo "Dependency-Track HIGH:     $DT_HIGH"

          jq --argjson dc "$DT_CRIT" --argjson dh "$DT_HIGH" \
            '. + {dependencytrack:{critical:$dc, high:$dh}}' \
            "$REPORTS_DIR/summary.json" > "$REPORTS_DIR/summary.tmp.json"
          mv "$REPORTS_DIR/summary.tmp.json" "$REPORTS_DIR/summary.json"
        '''
      }
    }

    stage('Security Gates') {
      steps {
        sh '''
          set -euo pipefail

          BANDIT_HIGH="$(jq -r '.bandit.high' "$REPORTS_DIR/summary.json")"
          DT_CRIT="$(jq -r '.dependencytrack.critical' "$REPORTS_DIR/summary.json")"
          DT_HIGH="$(jq -r '.dependencytrack.high' "$REPORTS_DIR/summary.json")"

          echo "Gate check => Bandit HIGH=$BANDIT_HIGH | DTrack CRIT=$DT_CRIT HIGH=$DT_HIGH"

          # Gate 1: Bandit HIGH > 0
          if [ "$BANDIT_HIGH" -gt 0 ]; then
            echo "FAIL: Bandit tiene vulnerabilidades HIGH."
            exit 1
          fi

          # Gate 2: Dependency-Track CRITICAL/HIGH > 0
          if [ "$DT_CRIT" -gt 0 ] || [ "$DT_HIGH" -gt 0 ]; then
            echo "FAIL: Dependency-Track tiene vulnerabilidades CRITICAL/HIGH."
            exit 1
          fi
        '''
      }
    }
  }

  post {
    always {
      withCredentials([string(credentialsId: 'defectdojo_api_token', variable: 'DOJO_TOKEN')]) {
        // IMPORTANTE: usamos ''' ... ''' para que Groovy NO interpole $DOJO_TOKEN
        sh(label: 'Upload results to DefectDojo', script: '''
          set -euo pipefail

          # Bandit -> DefectDojo
          if [ -f "$REPORTS_DIR/bandit.json" ]; then
            curl -sS -X POST "$DOJO_URL/api/v2/import-scan/" \
              -H "Authorization: Token $DOJO_TOKEN" \
              -F "scan_type=Bandit Scan" \
              -F "file=@$REPORTS_DIR/bandit.json" \
              -F "product_type_name=$PRODUCT_TYPE_NAME" \
              -F "product_name=$PRODUCT_NAME" \
              -F "engagement_name=$ENGAGEMENT_NAME" \
              -F "auto_create_context=true" \
              -F "close_old_findings=true" \
              -F "scan_date=$(date +%F)" > /dev/null
          fi

          # Gitleaks -> DefectDojo
          if [ -f "$REPORTS_DIR/gitleaks.json" ]; then
            curl -sS -X POST "$DOJO_URL/api/v2/import-scan/" \
              -H "Authorization: Token $DOJO_TOKEN" \
              -F "scan_type=Gitleaks Scan" \
              -F "file=@$REPORTS_DIR/gitleaks.json" \
              -F "product_type_name=$PRODUCT_TYPE_NAME" \
              -F "product_name=$PRODUCT_NAME" \
              -F "engagement_name=$ENGAGEMENT_NAME" \
              -F "auto_create_context=true" \
              -F "close_old_findings=true" \
              -F "scan_date=$(date +%F)" > /dev/null
          fi

          # Dependency-Track FPF -> DefectDojo
          if [ -f "$REPORTS_DIR/dtrack-fpf.json" ]; then
            curl -sS -X POST "$DOJO_URL/api/v2/import-scan/" \
              -H "Authorization: Token $DOJO_TOKEN" \
              -F "scan_type=Dependency Track Finding Packaging Format (FPF) Export" \
              -F "file=@$REPORTS_DIR/dtrack-fpf.json" \
              -F "product_type_name=$PRODUCT_TYPE_NAME" \
              -F "product_name=$PRODUCT_NAME" \
              -F "engagement_name=$ENGAGEMENT_NAME" \
              -F "auto_create_context=true" \
              -F "close_old_findings=true" \
              -F "scan_date=$(date +%F)" > /dev/null
          fi
        ''')
      }

      sh '''
        ls -lah "$REPORTS_DIR" || true
      '''
      archiveArtifacts artifacts: "reports/*", fingerprint: true
    }
  }
}

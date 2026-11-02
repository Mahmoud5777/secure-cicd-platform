$ErrorActionPreference = "Stop"

$ImageName = "mahmoud5777/secure-cicd-platform:latest"
$ContainerName = "secure-cicd-platform"
$Port = "8080"

Write-Host "=== Secure CI/CD Deployment ===" -ForegroundColor Cyan

# 1. Télécharger la dernière image
Write-Host "Pulling Docker image..."
docker pull $ImageName

if ($LASTEXITCODE -ne 0) {
    throw "Docker image download failed."
}

# 2. Arrêter et supprimer l'ancien conteneur
$ExistingContainer = docker ps -aq --filter "name=^/$ContainerName$"

if ($ExistingContainer) {
    Write-Host "Removing existing container..."
    docker rm -f $ContainerName
}

# 3. Démarrer le nouveau conteneur
Write-Host "Starting application..."

docker run -d `
    --name $ContainerName `
    --restart unless-stopped `
    -p "${Port}:8080" `
    $ImageName

if ($LASTEXITCODE -ne 0) {
    throw "Container startup failed."
}

# 4. Vérifier le statut du conteneur
Start-Sleep -Seconds 10

$ContainerStatus = docker inspect `
    --format '{{.State.Status}}' $ContainerName

if ($ContainerStatus -ne "running") {
    docker logs $ContainerName
    throw "Application container is not running."
}

Write-Host "Deployment successful!" -ForegroundColor Green
Write-Host "Application URL: http://localhost:8080"
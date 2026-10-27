
$body = @{
    model = "openai/gpt-oss-20b"
    messages = @(
        @{
            role = "user"
            content = "Reponds simplement : Groq fonctionne."
        }
    )
    max_completion_tokens = 100
} | ConvertTo-Json -Depth 5

try {
    $response = Invoke-RestMethod `
        -Uri "https://api.groq.com/openai/v1/chat/completions" `
        -Method Post `
        -Headers @{ Authorization = "Bearer $env:GROQ_API_KEY" } `
        -ContentType "application/json" `
        -Body $body

    $response.choices[0].message.content
}
catch {
    Write-Output "Echec de l'appel API."
    Write-Output $_.Exception.Message
}

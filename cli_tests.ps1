$passed = 0
$failed = 0

Write-Host "Running command-line tests..."
Write-Host ""

# --------------------------------------------------
# Test 1: Known-answer encryption
# --------------------------------------------------

$output = & .\xor_vigenere.exe encrypt --key 6b6579 --text hello

if ($LASTEXITCODE -eq 0 -and $output -eq "030015070a") {
    Write-Host "PASS: known-answer encryption"
    $passed++
}
else {
    Write-Host "FAIL: known-answer encryption"
    $failed++
}


# --------------------------------------------------
# Test 2: Known-answer decryption
# --------------------------------------------------

$output = & .\xor_vigenere.exe decrypt --key 6b6579 --ciphertext 030015070a

if ($LASTEXITCODE -eq 0 -and $output -eq "hello") {
    Write-Host "PASS: known-answer decryption"
    $passed++
}
else {
    Write-Host "FAIL: known-answer decryption"
    $failed++
}


# --------------------------------------------------
# Test 3: Empty key
# --------------------------------------------------

$output = & .\xor_vigenere.exe encrypt --key "" --text hello 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "PASS: empty key rejected"
    $passed++
}
else {
    Write-Host "FAIL: empty key accepted"
    $failed++
}


# --------------------------------------------------
# Test 4: Odd-length hexadecimal
# --------------------------------------------------

$output = & .\xor_vigenere.exe encrypt --key 123 --text hello 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "PASS: odd-length hex rejected"
    $passed++
}
else {
    Write-Host "FAIL: odd-length hex accepted"
    $failed++
}


# --------------------------------------------------
# Test 5: Invalid hexadecimal character
# --------------------------------------------------

$output = & .\xor_vigenere.exe encrypt --key 12G4 --text hello 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "PASS: invalid hex rejected"
    $passed++
}
else {
    Write-Host "FAIL: invalid hex accepted"
    $failed++
}


# --------------------------------------------------
# Test 6: Hex with whitespace
# --------------------------------------------------

$output = & .\xor_vigenere.exe encrypt --key " 49 " --text hello 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "PASS: hex whitespace rejected"
    $passed++
}
else {
    Write-Host "FAIL: hex whitespace accepted"
    $failed++
}


# --------------------------------------------------
# Test 7: Zero key length
# --------------------------------------------------

$output = & .\xor_vigenere.exe keygen --length 0 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "PASS: zero key length rejected"
    $passed++
}
else {
    Write-Host "FAIL: zero key length accepted"
    $failed++
}


# --------------------------------------------------
# Test 8: Negative key length
# --------------------------------------------------

$output = & .\xor_vigenere.exe keygen --length -5 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "PASS: negative key length rejected"
    $passed++
}
else {
    Write-Host "FAIL: negative key length accepted"
    $failed++
}


# --------------------------------------------------
# Test 9: Non-integer key length
# --------------------------------------------------

$output = & .\xor_vigenere.exe keygen --length abc 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "PASS: non-integer key length rejected"
    $passed++
}
else {
    Write-Host "FAIL: non-integer key length accepted"
    $failed++
}


# --------------------------------------------------
# Test 10: Missing key length
# --------------------------------------------------

$output = & .\xor_vigenere.exe keygen --length 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "PASS: missing key length rejected"
    $passed++
}
else {
    Write-Host "FAIL: missing key length accepted"
    $failed++
}


# --------------------------------------------------
# Test 11: Invalid UTF-8 after decryption
#
# Key 00 does not change the ciphertext byte.
# ff by itself is not valid UTF-8.
# --------------------------------------------------

$output = & .\xor_vigenere.exe decrypt --key 00 --ciphertext ff 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "PASS: invalid UTF-8 rejected"
    $passed++
}
else {
    Write-Host "FAIL: invalid UTF-8 accepted"
    $failed++
}


# --------------------------------------------------
# Test 12: Key generation format
# --------------------------------------------------

$output = & .\xor_vigenere.exe keygen --length 4

if ($LASTEXITCODE -eq 0 -and $output -match '^[0-9a-f]{8}$') {
    Write-Host "PASS: key generation format"
    $passed++
}
else {
    Write-Host "FAIL: key generation format"
    $failed++
}

# --------------------------------------------------
# Test 13: Multibyte UTF-8 encryption
# --------------------------------------------------

$cafe = "caf" + [char]0x00E9

$output = & .\xor_vigenere.exe encrypt --key 00 --text $cafe

if ($LASTEXITCODE -eq 0 -and $output -eq "636166c3a9") {
    Write-Host "PASS: UTF-8 encryption"
    $passed++
}
else {
    Write-Host "FAIL: UTF-8 encryption"
    $failed++
}


# --------------------------------------------------
# Test 14: Multibyte UTF-8 decryption
# --------------------------------------------------

$tempFile = "utf8_test_output.bin"

cmd /c ".\xor_vigenere.exe decrypt --key 00 --ciphertext 636166c3a9 > $tempFile"

$exitCode = $LASTEXITCODE

$bytes = [System.IO.File]::ReadAllBytes($tempFile)

# Convert output bytes to hex
$hexOutput = ($bytes | ForEach-Object {
    $_.ToString("x2")
}) -join ""

# Remove the newline printed by the program
$hexOutput = $hexOutput -replace "0d0a$", ""
$hexOutput = $hexOutput -replace "0a$", ""

Remove-Item $tempFile

if ($exitCode -eq 0 -and $hexOutput -eq "636166c3a9") {
    Write-Host "PASS: UTF-8 decryption"
    $passed++
}
else {
    Write-Host "FAIL: UTF-8 decryption"
    $failed++
}

# --------------------------------------------------
# Results
# --------------------------------------------------

Write-Host ""
Write-Host "Passed: $passed"
Write-Host "Failed: $failed"

if ($failed -eq 0) {
    Write-Host "All CLI tests passed."
    exit 0
}
else {
    Write-Host "Some CLI tests failed."
    exit 1
}
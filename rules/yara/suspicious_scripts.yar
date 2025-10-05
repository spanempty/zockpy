rule suspicious_scripts {
    strings:
        $powershell_enc = "powershell -enc"
        $base64 = "base64"
        $iex = "iex"
        $invoke_expression = "invoke-expression"
    condition:
        any of them
}

rule trojan {
    strings:
        $backdoor = "backdoor"
        $keylogger = "keylogger"
        $rat = "rat"
        $remote_access = "remote access"
    condition:
        any of them
}
